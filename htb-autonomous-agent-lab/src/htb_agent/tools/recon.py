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

from ..command_validator import validate, ValidationReport
from ..scope_guard import ScopeGuard, ScopeViolation, CommandScopeResult
from ..observation.parsers import parse_nmap_xml, NmapResult, NmapHost
from .runner import Runner, RunOutput


# (레이블, 명령 템플릿, 타임아웃초)
PORTSCAN_PLAN: list[tuple[str, str, int]] = [
    ("기본 서비스 스캔", "nmap -sV -oX - {t}", 300),
    ("핑 생략(-Pn)", "nmap -Pn -sV -oX - {t}", 300),
    ("TCP connect(-Pn -sT)", "nmap -Pn -sT -sV -oX - {t}", 600),
    ("전체 포트(-Pn -p-)", "nmap -Pn -p- -oX - {t}", 900),
]

Approver = Callable[[str, ValidationReport, CommandScopeResult], bool]


def auto_approve_in_scope(cmd: str, vrep: ValidationReport,
                          sres: CommandScopeResult) -> bool:
    """검증 통과 + 범위내(추가확인 불필요)일 때만 자동 승인. 그 외 거부."""
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
                 hosts_map: dict[str, str] | None = None):
        self.guard = guard
        self.runner = runner
        self.approver = approver
        self.max_attempts = max_attempts
        self.hosts_map = hosts_map

    def run_portscan(self) -> ReconReport:
        if self.guard.bound_target is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target)
        report = ReconReport(target=target, status="escalate")

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
            # 4) 실행
            out: RunOutput = self.runner.run(cmd, timeout=timeout)
            rec.ran = out.launched
            if not out.launched:
                rec.note = f"실행 실패: {out.error}"
                continue
            res = (parse_nmap_xml(out.stdout) if out.stdout.strip()
                   else NmapResult(parse_error=out.stderr or "빈 출력"))
            rec.result = res

            if _satisfactory(res):
                h = res.first_host()
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
        report.message = (
            "모든 폴백 소진 — " + ("호스트는 up 이나 열린 포트 미발견" if up
                                   else "호스트 응답 없음") + ". 사람 개입 필요(자동 반복 안 함)."
        )
        return report
