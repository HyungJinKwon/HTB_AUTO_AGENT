"""
Recon Executor — 유한 폴백 체인 포트스캔 (무한루프 방지)
========================================================

포트스캔을 '경우의 수'로 여러 방안 시도하되, **유한한 계획 리스트**를 순서대로
소비한다. `while True` 없음 — 계획을 다 쓰거나 max_attempts 에 도달하면 멈추고
사람에게 에스컬레이션한다.

각 시도는 반드시 다음을 통과한 뒤에만 실행된다:
  1. CommandValidator (문법·형식·실행가능성)
  2. ScopeGuard (대상이 HTB 범위인지)
  3. Approver (승인제 — 기본: 범위내+검증통과만 자동승인, 아니면 사람 확인)

폴백 순서(포트스캔):
  기본 -sV  →  핑 생략 -Pn  →  TCP connect -sT  →  전체 포트 -p-
스캔이 '다운처럼 보이면' 다음 방안으로 넘어간다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..command_validator import ValidationReport, validate
from ..observation.parsers import NmapHost, NmapResult, parse_nmap_xml
from ..scope_guard import CommandScopeResult, ScopeGuard, ScopeViolation
from ..util import network_blocked
from .runner import Runner, RunOutput

# (레이블, 명령 템플릿, 타임아웃초)
# -sC(기본 NSE 스크립트) + -sV(버전) 은 HTB/CTF 표준 첫 스캔. 폴백 단계로 -Pn(핑생략)·
# -sT(TCP connect)·-p-(전체 포트)로 경우의 수를 넓힌다. 전체포트는 속도 위해 -sC 생략 후
# 발견 포트 대상 정밀 스캔을 별도 수행한다.
PORTSCAN_PLAN: list[tuple[str, str, int]] = [
    ("기본 서비스+스크립트 스캔", "nmap -sC -sV -oX - {t}", 300),
    ("핑 생략(-Pn)", "nmap -Pn -sC -sV -oX - {t}", 300),
    ("TCP connect(-Pn -sT)", "nmap -Pn -sT -sC -sV -oX - {t}", 600),
    ("전체 포트(-Pn -p-)", "nmap -Pn -p- -oX - {t}", 900),
]

Approver = Callable[[str, ValidationReport, CommandScopeResult], bool]


def auto_approve_in_scope(cmd: str, vrep: ValidationReport,
                          sres: CommandScopeResult) -> bool:
    """검증 통과 + 범위내(추가확인 불필요) + 검토 불필요일 때만 자동 승인. 그 외 거부.
    동적·원격 코드 실행(vrep.review)은 무프롬프트 모드에서 실행하지 않는다(수동 제안으로)."""
    return vrep.ok and sres.auto_allowed and not vrep.review


def auto_approve_contained(cmd: str, vrep: ValidationReport,
                           sres: CommandScopeResult) -> bool:
    """완전자율 + egress 강제 샌드박스 전용 승인. 검증 통과 + 범위내면 동적·원격 코드 실행
    (review)도 자동 승인한다 — 실행 내용을 정적으로 알 수 없어도 네트워크는 컨테이너
    방화벽이 타겟 대역으로 묶고, 명령은 비root 로 정책을 바꿀 수 없기 때문이다.
    파괴명령(검증 실패)·범위 밖 대상은 여전히 거부."""
    return vrep.ok and sres.auto_allowed


@dataclass
class AttemptRecord:
    label: str
    command: str
    validated: bool = False
    scope_ok: bool = False
    approved: bool = False
    ran: bool = False
    note: str = ""
    result: NmapResult | None = None


@dataclass
class ReconReport:
    target: str
    status: str                      # success / escalate
    attempts: list[AttemptRecord] = field(default_factory=list)
    host: NmapHost | None = None
    message: str = ""

    def summary(self) -> str:
        head = {"success": "✅ 성공", "escalate": "⚠️ 에스컬레이션"}.get(self.status, self.status)
        lines = [f"{head} — 대상 {self.target}: {self.message}",
                 f"시도 {len(self.attempts)}회:"]
        for i, a in enumerate(self.attempts, 1):
            flags = []
            flags.append("검증" + ("O" if a.validated else "X"))
            flags.append("범위" + ("O" if a.scope_ok else "X"))
            flags.append("승인" + ("O" if a.approved else "X"))
            flags.append("실행" + ("O" if a.ran else "X"))
            lines.append(f"  {i}. {a.label} [{'/'.join(flags)}]"
                         + (f" — {a.note}" if a.note else ""))
        return "\n".join(lines)


def _satisfactory(result: NmapResult) -> bool:
    """호스트가 up 이고 열린 포트가 하나라도 있으면 성공으로 본다."""
    h = result.first_host()
    return bool(result.any_up and h and h.open_ports)


class ReconExecutor:
    def __init__(self, guard: ScopeGuard, runner: Runner,
                 approver: Approver = auto_approve_in_scope,
                 max_attempts: int = 4,
                 hosts_map: dict[str, str] | None = None,
                 is_tool_available: "Callable[[str], bool] | None" = None,
                 extra_ports: "list[int] | None" = None,
                 scan_timeout: float = 1.0,
                 socket_probe=None,
                 real_exec: "bool | None" = None):
        self.guard = guard
        self.runner = runner
        self.approver = approver
        self.max_attempts = max_attempts
        self.hosts_map = hosts_map
        # nmap 가용 여부(주입 가능). 없으면 순수 파이썬 TCP-connect 폴백으로 포트 발견.
        import shutil
        self.is_tool_available = is_tool_available or (lambda b: shutil.which(b) is not None)
        self.extra_ports = [int(p) for p in (extra_ports or [])]
        self.scan_timeout = scan_timeout
        self._socket_probe = socket_probe
        # 소켓 폴백은 '실제 실행' 러너에서만(FakeRunner 테스트에서 실제 네트워크 접속 금지).
        # 명시값이 없으면 러너의 real_exec 능력에서 유도(FakeRunner=False → 폴백 안 함).
        self.real_exec = (real_exec if real_exec is not None
                          else getattr(runner, "real_exec", True))

    def _socket_fallback(self, target: str) -> "AttemptRecord | None":
        """nmap 없을 때 파이썬 TCP-connect 스캔. 바인딩 타겟만 스캔(범위 밖 불가).
        호스트명 타겟은 소켓이 OS 해석기로 연결하므로 그대로 사용한다."""
        from .portscan_fallback import DEFAULT_PORTS, socket_scan
        ports = list(DEFAULT_PORTS) + [p for p in self.extra_ports if p not in DEFAULT_PORTS]
        rec = AttemptRecord(label="소켓 폴백(nmap 미설치 · TCP connect)",
                            command=f"[python socket-scan] {target} ({len(ports)} 포트)",
                            validated=True, scope_ok=True, approved=True)
        try:
            res = socket_scan(target, ports, timeout=self.scan_timeout,
                              probe=self._socket_probe)
            rec.ran = True
            rec.result = res
            h = res.first_host()
            rec.note = (f"열린 포트 {h.open_ports}" if (h and h.open_ports)
                        else "열린 포트 없음")
        except Exception as e:   # noqa: BLE001 — 폴백 실패가 세션을 깨지 않도록
            rec.note = f"소켓 스캔 예외: {type(e).__name__}: {e}"
        return rec

    def run_portscan(self) -> ReconReport:
        if self.guard.bound_target is None and self.guard.bound_host is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        # 호스트명 타겟(CTF)도 지원: IP 가 없으면 호스트명으로 스캔(nmap 가 해석)
        target = str(self.guard.bound_target or self.guard.bound_host)
        report = ReconReport(target=target, status="escalate")

        # 오프라인/네트워크 차단(ASSASSIN_NO_NET): 실제 실행 러너에서 '진짜 nmap/소켓 스캔'을
        # 내보내지 않는다. NO_NET 은 '실제 아웃바운드 없음'을 뜻하므로, 실 러너로 recon 을 돌리면
        # 도달 불가 타겟에 대해 nmap 이 자신의 타임아웃까지(분 단위) 블록돼 테스트·오프라인 실행이
        # 간헐적으로 멈춘다. 여기서 명시적으로 생략해 그 행(hang)을 구조적으로 제거한다. FakeRunner
        # (real_exec=False)는 실제 네트워크를 쓰지 않으므로 이 가드의 대상이 아니다(가짜 결과 그대로).
        if self.real_exec and network_blocked():
            report.attempts.append(AttemptRecord(
                label="오프라인(ASSASSIN_NO_NET) — 실제 스캔 생략",
                command="[skipped: ASSASSIN_NO_NET]",
                validated=True, scope_ok=True, approved=True, ran=False,
                note="ASSASSIN_NO_NET=1 — 실제 네트워크 스캔(nmap/소켓) 생략(오프라인·테스트)"))
            report.message = ("오프라인 모드(ASSASSIN_NO_NET) — 실제 포트스캔 미실행. "
                              "실제 스캔이 필요하면 ASSASSIN_NO_NET 을 해제하라.")
            return report

        # nmap 이 없으면 순수 파이썬 TCP-connect 폴백으로 포트를 발견한다(바인딩 타겟만).
        # 단, 실제 실행 러너일 때만 — FakeRunner(테스트)에선 실제 소켓 접속을 하지 않는다.
        if self.real_exec and not self.is_tool_available("nmap"):
            fb = self._socket_fallback(target)
            if fb is not None:
                report.attempts.append(fb)
                if fb.result is not None and _satisfactory(fb.result):
                    h = fb.result.first_host()
                    report.status = "success"
                    report.host = h
                    report.message = (f"소켓 폴백(nmap 미설치) 성공 — 열린 포트 "
                                      f"{h.open_ports if h else []}")
                    return report
                report.host = fb.result.first_host() if fb.result else None
                report.message = ("소켓 폴백(nmap 미설치): 열린 포트 미발견 — nmap 설치 권장"
                                  "(sudo apt install -y nmap). 사람 개입 필요.")
                return report

        for idx, (label, tmpl, timeout) in enumerate(PORTSCAN_PLAN):
            if idx >= self.max_attempts:   # 유한 상한 — 무한루프 방지
                break
            cmd = tmpl.format(t=target)
            rec = AttemptRecord(label=label, command=cmd)
            report.attempts.append(rec)

            # 1) 검증
            vrep = validate(cmd)
            rec.validated = vrep.ok
            if not vrep.ok:
                rec.note = "검증 실패: " + "; ".join(str(i) for i in vrep.errors)
                continue
            # 2) 범위
            try:
                sres = self.guard.inspect_command(cmd, hosts_map=self.hosts_map)
            except ScopeViolation as e:
                rec.note = f"범위 오류: {e}"
                continue
            rec.scope_ok = sres.auto_allowed
            # 3) 승인
            rec.approved = self.approver(cmd, vrep, sres)
            if not rec.approved:
                rec.note = "미승인(범위밖/사용자 거부)"
                continue
            # 4) 실행 — 러너 예외를 흡수해 한 시도의 실패가 정찰 세션 전체를
            #    중단시키지 않도록 한다(열거 경로의 _safe_run 과 동일한 보증).
            try:
                out: RunOutput = self.runner.run(cmd, timeout=timeout)
            except Exception as e:   # noqa: BLE001
                rec.note = f"러너 예외: {type(e).__name__}: {e}"
                continue
            rec.ran = out.launched
            if not out.launched:
                rec.note = f"실행 실패: {out.error}"
                continue
            res = (parse_nmap_xml(out.stdout) if out.stdout.strip()
                   else NmapResult(parse_error=out.stderr or "빈 출력"))
            rec.result = res

            h = res.first_host()
            if _satisfactory(res) and h is not None:   # _satisfactory 가 호스트 존재를 보장(타입 명시용)
                report.status = "success"
                report.host = h
                report.message = f"{label} 성공 — 열린 포트 {h.open_ports}"
                return report
            rec.note = ("다운처럼 보임 → 다음 방안" if res.seems_down
                        else "열린 포트 없음 → 다음 방안")

        # 계획 소진 — 마지막으로 파악된 호스트를 담아 에스컬레이션
        last_host = next((a.result.first_host() for a in reversed(report.attempts)
                          if a.result and a.result.first_host()), None)
        report.host = last_host
        up = last_host and last_host.state == "up"
        if not any(a.ran for a in report.attempts):
            # 한 번도 실행되지 못함 = 도구·실행 환경 문제(대상 응답과 무관) — '응답 없음'으로 오해 금지
            why = next((a.note for a in report.attempts if a.note), "")
            report.message = ("스캔이 한 번도 실행되지 못함 — 도구/실행 환경 문제(대상 문제 아님)"
                              + (f": {why}" if why else "") + ". 사람 개입 필요(자동 반복 안 함).")
            return report
        report.message = (
            "모든 폴백 소진 — " + ("호스트는 up 이나 열린 포트 미발견" if up
                                   else "호스트 응답 없음") + ". 사람 개입 필요(자동 반복 안 함)."
        )
        return report
