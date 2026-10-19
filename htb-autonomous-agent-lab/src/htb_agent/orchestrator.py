"""
Orchestrator — 유한 단계 상태머신 (자동화 + 무한루프 금지)
==========================================================

단계(phase)를 '유한하게' 진행한다. 각 단계는 한 번씩(내부 폴백은 자체 상한)
실행되고, 다음 단계로 넘어간다. `while True` 없음 — 전체는 선형 파이프라인 +
각 단계의 유한 상한으로 구성된다.

  RECON   : 포트스캔(ReconExecutor, 유한 폴백)
  PROFILE : OS/역할 판정(Linux vs Windows-AD)
  ENUM    : 지식베이스(KB)로 다음 액션 선택 → 자동실행(승인 게이트 통과분, 상한)
  REPORT  : 자동실행 못 한 '수동' 제안 + 결과 요약

자동화이지만 실행은 승인제: 각 enum 명령도 검증→범위→승인 3관문을 통과해야
실행된다. 민감값({user}/{pass} 등)이 남은 제안은 자동실행하지 않고 수동 제안으로
남긴다.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Callable

from .util import binary_of
from .command_validator import validate, ValidationReport
from .scope_guard import ScopeGuard, ScopeViolation, CommandScopeResult
from .observation.parsers import NmapHost
from .observation.compressor import profile_from_nmap
from .observation.summarize import summarize_tool_output
from .target_profiler import ProfileResult
from .knowledge import KnowledgeBase
from .creds import CredentialVault
from .audit import NullAudit
from .research import OneDayResearch
from .llm.router import LLMRouter
from .vuln import VulnKB, VulnMatch, extract_vuln_ids
from .tiering import tier_for
from .exploit_loop import ExploitLoop, Gate
from .attempt import Ledger
from .generators import make_llm_generator, make_flag_generator
from .clues import ClueStore
from .flag import FlagHit as _FlagHit
from .verify import (FLAG_GENUINE as _FLAG_GENUINE,
                     FLAG_UNDEMONSTRATED as _FLAG_UNDEMONSTRATED,
                     is_capability as _is_capability)
from .flag import FlagHit, scan as scan_flags
from .state import SessionState, StateStore, host_to_dict, host_from_dict
from .tools.runner import Runner
from .tools.registry import TOOLS
from .tools.recon import ReconExecutor, ReconReport, auto_approve_in_scope, Approver


# 모의해킹 진행 단계(순서대로). (key, 표시라벨)
PENTEST_PHASES: list[tuple[str, str]] = [
    ("enum", "열거 (Enumeration)"),
    ("access", "초기 침투 (Initial Access)"),
    ("privesc", "권한 상승 (Privilege Escalation)"),
    ("lateral", "측면 이동 (Lateral Movement)"),
]
_PHASE_LABEL = dict(PENTEST_PHASES)

# 익스플로잇 루프로 도는 단계(탐지→실행). 나머지(enum)는 순수 열거.
EXPLOIT_PHASES = {"access", "privesc", "lateral"}


@dataclass
class EnumFinding:
    command: str
    ran: bool = False
    note: str = ""
    output: str = ""
    phase: str = "enum"


@dataclass
class OrchestrationReport:
    target: str
    status: str = "pending"          # done / escalate
    recon: ReconReport | None = None
    host: NmapHost | None = None
    profile: ProfileResult | None = None
    enum_findings: list[EnumFinding] = field(default_factory=list)
    llm_findings: list[EnumFinding] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    detected_cve: list[str] = field(default_factory=list)
    detected_cwe: list[str] = field(default_factory=list)
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    one_day_leads: list[dict] = field(default_factory=list)
    one_day_warnings: list[str] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)
    footholds: list[str] = field(default_factory=list)      # 익스플로잇 루프 획득
    exploit_report: str = ""                                 # 루프 종료 리포트
    message: str = ""

    @property
    def user_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "user"), None)

    @property
    def root_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "root"), None)

    def summary(self) -> str:
        lines = [f"# 오케스트레이션 — {self.target} [{self.status}] {self.message}".rstrip()]
        if self.recon:
            lines.append("\n## RECON")
            lines.append(self.recon.summary())
        if self.profile:
            lines.append("\n## PROFILE")
            lines.append(self.profile.summary())
        # 모의해킹 단계 순서대로 그룹화 출력
        all_findings = self.enum_findings + self.llm_findings
        for key, label in PENTEST_PHASES:
            group = [f for f in all_findings if f.phase == key]
            if group:
                lines.append(f"\n## 단계: {label}")
                for f in group:
                    mark = "▶" if f.ran else "·"
                    lines.append(f"  {mark} {f.command}" + (f"  — {f.note}" if f.note else ""))
                    if f.output:
                        lines.append(f"      {f.output}")
        if self.detected_cve or self.detected_cwe or self.vuln_matches:
            lines.append("\n## VULN (탐지된 취약점 — 수동 검증/익스플로잇 필요)")
            if self.detected_cve:
                lines.append(f"  탐지 CVE: {', '.join(self.detected_cve)}")
            if self.detected_cwe:
                lines.append(f"  탐지 CWE: {', '.join(self.detected_cwe)}")
            for m in self.vuln_matches:
                sev = f"[{m.severity}] " if m.severity else ""
                ids = " ".join(m.cve + m.cwe)
                lines.append(f"  ⚠️ {sev}{m.name} ({ids}) — 매칭:{m.matched_on}")
                if m.note:
                    lines.append(f"       비고: {m.note}")
                for s in m.suggest:
                    lines.append(f"       제안: {s}")
        if self.one_day_leads or self.one_day_warnings:
            lines.append("\n## 1-day 후보 (메타데이터 검색 — 취약 여부·실행 가능성 미검증)")
            for lead in self.one_day_leads:
                lines.append(f"  · {lead['source']} {lead['id']}: {lead['title']} ({lead['url']})")
            for warning in self.one_day_warnings:
                lines.append(f"  ⚠️ {warning}")
        if self.flags:
            lines.append("\n## 🚩 플래그 (FLAG)")
            lines.append(f"  user.txt: {self.user_flag or '미획득'}")
            lines.append(f"  root.txt: {self.root_flag or '미획득'}")
            # 획득 경로 — undemonstrated 는 '플래그는 맞지만 공략 증거 없음'. 정직하게 표시.
            for f in self.flags:
                if f.provenance == "undemonstrated":
                    lines.append(f"  ⚠️ {f.kind}: 미증명(undemonstrated) — 선행 익스플로잇 증거 없음")
            for f in self.flags:
                if f.kind == "unknown":
                    lines.append(f"  (미분류) {f.value} ← {f.source}")
        if self.manual_suggestions:
            lines.append("\n## 수동 제안 (크리덴셜 등 필요 — 승인/입력 후 실행)")
            for s in self.manual_suggestions:
                lines.append(f"  · {s}")
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, guard: ScopeGuard, runner: Runner, kb: KnowledgeBase,
                 approver: Approver = auto_approve_in_scope,
                 hosts_map: dict[str, str] | None = None,
                 max_enum: int = 6,
                 recon_max_attempts: int = 4,
                 max_rounds: int = 2,
                 llm_router: LLMRouter | None = None,
                 max_llm: int = 5,
                 vuln_kb: VulnKB | None = None,
                 vault: CredentialVault | None = None,
                 state_store: StateStore | None = None,
                 resume: bool = False,
                 audit=None,
                 phases: list[tuple[str, str]] | None = None,
                 is_tool_available: Callable[[str], bool] | None = None,
                 exploit_max_rounds: int = 8,
                 exploit_timebox: int = 1800,
                 exploit_attempt_timebox: int = 180,
                 one_day_research: OneDayResearch | None = None,
                 enable_one_day: bool = True):
        self.guard = guard
        self.runner = runner
        self.kb = kb
        self.approver = approver
        self.hosts_map = hosts_map
        self.max_enum = max_enum
        self.recon_max_attempts = recon_max_attempts
        self.max_rounds = max(1, max_rounds)
        self.llm_router = llm_router
        self.max_llm = max_llm
        self.vuln_kb = vuln_kb
        self.vault = vault
        self.state_store = state_store
        self.resume = resume
        self.audit = audit or NullAudit()
        if vault is not None and hasattr(self.audit, "add_secrets"):
            self.audit.add_secrets(vault.secret_values())
        self._redact = vault.redact if vault is not None else (lambda value: value)
        self.one_day_research = (
            one_day_research or OneDayResearch(audit=self.audit)
        ) if enable_one_day else None
        if self.one_day_research and isinstance(getattr(self.one_day_research, "audit", None), NullAudit):
            self.one_day_research.audit = self.audit
        # 라우터의 ctx_build·llm_call·거절 이벤트가 같은 감사 로그에 남게 한다
        if llm_router is not None and isinstance(getattr(llm_router, "audit", None), NullAudit):
            llm_router.audit = self.audit
        self.phases = phases or PENTEST_PHASES
        self.exploit_max_rounds = exploit_max_rounds
        self.exploit_timebox = exploit_timebox
        self.exploit_attempt_timebox = exploit_attempt_timebox
        self._ledger: Ledger | None = None       # run() 마다 새로, 익스플로잇 단계 공유
        self._clues = ClueStore()                 # 환경 단서 누적(교차단계 재사용)
        self._seen_cmds: set[str] = set()         # 열거 단계가 이미 돌린 명령(KB 제안 중복 제거용)
        self._tools_cache: list[str] | None = None
        # 도구 설치 여부 판단(주입 가능 — 테스트에서 대체)
        self.is_tool_available = is_tool_available or (lambda b: shutil.which(b) is not None)

    def _installed_tools(self) -> list[str]:
        """설치된 도구 이름(런당 1회). 모델이 없는 도구를 지어내 호출을 낭비하지 않게
        정적 시스템 프롬프트에 실린다(~150토큰, 접두사 캐시 대상)."""
        if self._tools_cache is None:
            self._tools_cache = sorted(t.key for t in TOOLS
                                       if any(self.is_tool_available(b) for b in t.binaries))
        return self._tools_cache

    def run(self) -> OrchestrationReport:
        if self.guard.bound_target is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target)
        report = OrchestrationReport(target=target)
        self.audit.event("session_start", target=target, resume=self.resume,
                         ranges=[str(n) for n in self.guard.allowed_target_cidrs])

        # 재개: 저장된 상태에 포트가 있으면 RECON 을 건너뛰고 재사용
        prior: SessionState | None = None
        host = None
        if self.resume and self.state_store and self.state_store.exists(target):
            prior = self.state_store.load(target)
            if prior and prior.host:
                host = host_from_dict(prior.host)
                report.message = "(재개: 저장된 RECON 재사용 — 재스캔 생략) "

        # ── PHASE 1: RECON (유한 폴백) — 재개로 host 확보 시 생략 ──
        if host is None:
            recon = ReconExecutor(self.guard, self.runner, self.approver,
                                  max_attempts=self.recon_max_attempts,
                                  hosts_map=self.hosts_map).run_portscan()
            report.recon = recon
            host = recon.host
        report.host = host
        self.audit.event("recon", status=(report.recon.status if report.recon else "resumed"),
                         open_ports=host.open_ports if host else [])
        if host is None or not host.open_ports:
            report.status = "escalate"
            report.message += "열린 포트 미확보 — 다음 단계 불가. 사람 개입 필요."
            self._persist(report, prior)
            self.audit.event("session_end", status=report.status, message=report.message)
            return report

        # ── PHASE 2: PROFILE ──
        prof = profile_from_nmap(host)
        report.profile = prof
        self.audit.event("profile", os=prof.os_class.value, confidence=prof.confidence,
                         is_dc=prof.is_domain_controller)
        # Nmap script output can already contain a CVE. Query it before broad
        # product/version metadata so the one bounded NVD request prefers it.
        self._run_vuln(report, host, target)
        if self.one_day_research:
            self._run_one_day(report, host, report.detected_cve)

        # ── PHASE 3: 모의해킹 단계 '순서대로' 진행 ──
        # enum → access → privesc → lateral 순. 각 단계는 KB(해당 phase)+LLM 적응
        # 라운드를 돌리되, 전역 상한(max_enum·max_llm)·라운드 상한·조기종료로 유한.
        self._ledger = Ledger()
        self._clues = ClueStore()        # 원장과 함께 run() 마다 초기화
        seen_cmds = self._seen_cmds = set()
        phases_run: list[str] = []
        for key, label in self.phases:
            phase_before = len(report.enum_findings) + len(report.llm_findings)
            for _rnd in range(self.max_rounds):
                added = self._enum_round(report, host, prof, target, seen_cmds,
                                         self.max_enum - len(report.enum_findings), key)
                if self.llm_router is not None:
                    added += self._llm_round(report, host, prof, target, seen_cmds,
                                             self.max_llm - len(report.llm_findings), key,
                                             round_idx=_rnd)
                if added == 0:
                    break
            ran = len(report.enum_findings) + len(report.llm_findings) > phase_before
            # 침투·권한상승·측면이동은 '탐지→실행' 루프를 추가로 돌린다. 열거(위)는
            # 그대로 관측을 쌓고, 루프가 그 관측 위에서 기존 도구로 실제 공격을 시도.
            if key in EXPLOIT_PHASES and self._exploit_phase(report, host, prof, target, key):
                ran = True
            if ran:
                phases_run.append(key)
            if report.root_flag:          # root 플래그 확보 시 조기 종료
                break

        # ── PHASE 3.7: VULN (CVE/CWE 탐지 + 매핑) ──
        self._run_vuln(report, host, target)
        if self.one_day_research:
            self._run_one_day(report, host, report.detected_cve)

        # NSE 취약점 스크립트 보수적 제안(실행은 무겁고 길어 수동 제안으로)
        if host.open_ports:
            ports = ",".join(str(p) for p in host.open_ports)
            report.manual_suggestions.append(
                f"nmap -sV --script vuln -p {ports} {target}   # NSE 취약점 스캔(수동)")

        # ── PHASE 4: REPORT ──
        report.status = "done"
        flag_state = f"user={'O' if report.user_flag else 'X'} root={'O' if report.root_flag else 'X'}"
        report.message += (f"OS={prof.os_class.value}({prof.tag}), "
                           f"진행단계 {'→'.join(phases_run) or '없음'}, "
                           f"KB enum {len(report.enum_findings)}건, "
                           f"LLM {len(report.llm_findings)}건, 플래그[{flag_state}]")
        self._persist(report, prior)
        self.audit.event("vuln", cve=report.detected_cve, cwe=report.detected_cwe,
                         matches=[m.name for m in report.vuln_matches])
        self.audit.event("session_end", status=report.status, message=report.message)
        return report

    def _persist(self, report: OrchestrationReport, prior: SessionState | None) -> None:
        """진행 상태를 저장(중단/재개용). state_store 없으면 no-op."""
        if self.state_store is None:
            return
        st = prior or SessionState(target=report.target)
        st.allowed_ranges = [str(n) for n in self.guard.allowed_target_cidrs]
        st.attacker_ips = [str(ip) for ip in self.guard.attacker_ips]
        st.recon_status = report.recon.status if report.recon else (st.recon_status or "resumed")
        if report.host is not None:
            st.host = host_to_dict(report.host)
        if report.profile is not None:
            st.profile = {"os_class": report.profile.os_class.value,
                          "confidence": report.profile.confidence,
                          "is_dc": report.profile.is_domain_controller}
        fin = lambda f: {"command": f.command, "ran": f.ran, "note": f.note, "output": f.output}
        if report.enum_findings:
            st.enum_findings = [fin(f) for f in report.enum_findings]
        if report.llm_findings:
            st.llm_findings = [fin(f) for f in report.llm_findings]
        if report.manual_suggestions:
            st.manual_suggestions = report.manual_suggestions
        if report.detected_cve:
            st.detected_cve = report.detected_cve
        if report.detected_cwe:
            st.detected_cwe = report.detected_cwe
        if self.vault is not None and self.vault.creds:
            st.credentials = self.vault.to_public_list()
        elif st.credentials:
            # Rewrite pre-redaction state files on the next successful run.
            st.credentials = [
                {
                    "username": row.get("username", "") if isinstance(row.get("username"), str) else "",
                    "domain": row.get("domain") if isinstance(row.get("domain"), str) else None,
                    "source": row.get("source", "legacy-state")
                    if isinstance(row.get("source", "legacy-state"), str) else "legacy-state",
                    "has_password": bool(row.get("has_password") or row.get("password")),
                    "has_nt_hash": bool(row.get("has_nt_hash") or row.get("nt_hash")),
                }
                for row in st.credentials if isinstance(row, dict)
            ]
        if report.flags:
            st.flags = [{"value": f.value, "kind": f.kind, "source": f.source}
                        for f in report.flags]
        st.add_history(report.message.strip() or report.status)
        self.state_store.save(st)

    def _enum_round(self, report: OrchestrationReport, host: NmapHost,
                    prof: ProfileResult, target: str,
                    seen: set[str], budget: int, phase: str = "enum") -> int:
        """해당 단계(phase)의 KB 제안 한 라운드. 새로 시도한 명령 수 반환."""
        if budget <= 0:
            return 0
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
        attempted = 0
        for rec in recs:
            for tmpl in rec.suggestions:
                for cmd, runnable in self._expand(tmpl, target):
                    if cmd in seen:
                        continue
                    seen.add(cmd)
                    if not runnable:
                        report.manual_suggestions.append(
                            cmd + f"   # [{_PHASE_LABEL.get(phase, phase)}] {rec.rule_name}")
                        continue
                    if attempted >= budget:
                        report.manual_suggestions.append(cmd + "   # (상한 초과 — 수동)")
                        continue
                    self._attempt(report, report.enum_findings, cmd, phase)
                    attempted += 1
        return attempted

    def _expand(self, tmpl: str, target: str) -> list[tuple[str, bool]]:
        """볼트가 있으면 자격증명으로 플레이스홀더를 채워 확장, 없으면 {t}만 치환."""
        if self.vault is not None:
            return self.vault.expand(tmpl, target)
        cmd, auto = self.kb.format_suggestion(tmpl, target)
        return [(cmd, auto)]

    def _llm_round(self, report: OrchestrationReport, host: NmapHost,
                   prof: ProfileResult, target: str,
                   seen: set[str], budget: int, phase: str = "enum",
                   round_idx: int = 0) -> int:
        """해당 단계의 LLM 제안 한 라운드. 이전 관측을 컨텍스트에 반영(적응).

        티어는 (단계, 라운드)로 결정한다 — 룰 [2-5]. 열거는 저렴/로컬에서 시작하고
        막힐수록(round_idx↑) 올린다. floor 는 라우터 기본 티어(사용자 강제값)."""
        if budget <= 0:
            return 0
        tier = tier_for(phase, round_idx, floor=self.llm_router.default_tier)
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
        prior = [f"{f.command} => {f.output}"
                 for f in (report.enum_findings + report.llm_findings) if f.output]
        context = {
            "phase": _PHASE_LABEL.get(phase, phase),
            "profile": prof.summary(),
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            "kb": [f"{r.rule_name}: {', '.join(r.suggestions)}" for r in recs[:5]],
            "notes": self.kb.notes[:3],
            "findings": prior[-10:],
            "tools": self._installed_tools(),
            "research": self._research_context(report),
        }
        try:
            cmds = self.llm_router.suggest_commands(context, target, tier=tier,
                                                    max_items=budget)
        except Exception as e:  # LLM 백엔드 오류는 전체를 깨지 않는다
            report.manual_suggestions.append(f"(LLM 제안 실패: {e})")
            return 0
        self.audit.event("llm_round", phase=phase, round=round_idx, tier=tier.value)
        attempted = 0
        for cmd in cmds:
            if cmd in seen:
                continue
            seen.add(cmd)
            if attempted >= budget:
                break
            self._attempt(report, report.llm_findings, cmd, phase)
            attempted += 1
        return attempted

    # ── 익스플로잇 루프 (access/privesc/lateral) ─────────────────────
    def _build_generators(self, report: OrchestrationReport, host: NmapHost,
                          prof: ProfileResult, target: str, phase: str) -> list:
        """후보 생성원 구성. 기존 도구를 고르는 LLM + 결정적 플래그 캡처."""
        gens = []
        # 누적 관측에서 단서 수집(교차단계 재사용) — 생성 직전에 최신화
        for f in report.enum_findings + report.llm_findings:
            self._clues.harvest(f.output)
        for b in self._banners(host):
            self._clues.harvest(b)
        if self.llm_router is not None:
            services = [p.service for p in host.ports if p.state == "open" and p.service]
            recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
            matches = report.vuln_matches or (self.vuln_kb.match(self._banners(host), target)
                                              if self.vuln_kb else [])
            # 이미 돌린 제안은 KB 에서 뺀다 — 열거 라운드가 자동 실행한 명령을 컨텍스트에
            # 다시 실어 모델이 그대로 되풀이하게 만드는 낭비를 막는다.
            kb_lines = []
            for r in recs:
                cmds = [self.kb.format_suggestion(t, target)[0] for t in r.suggestions]
                if all(c in self._seen_cmds or self._ledger.already_ran(c) for c in cmds):
                    continue
                kb_lines.append(f"{r.rule_name}: {' ; '.join(cmds[:2])}")
            base_context = {
                "phase": _PHASE_LABEL.get(phase, phase),
                "profile": prof.summary(),
                "open_ports": [str(p) for p in host.ports if p.state == "open"],
                "kb": kb_lines[:8],
                "notes": self.kb.notes[:3],
                "tools": self._installed_tools(),
                "cve": [f"{m.name}: {', '.join(m.cve)} → {', '.join(m.suggest)}"
                        for m in matches[:5]],
                "research": self._research_context(report),
                "creds": [c.label() for c in (self.vault.creds if self.vault else [])][:5],
                "clues": self._clues.context_lines(),
            }
            gens.append(make_llm_generator(self.llm_router, base_context, target, phase))
        # 플래그 캡처는 LLM 유무와 무관하게(자격증명/셸이 있으면) 돈다
        gens.append(make_flag_generator(self.vault, target, prof.os_class.value, phase))
        return gens

    def _known_surfaces(self, host: NmapHost) -> list[str]:
        return [f"{p.service or 'svc'}:{p.port}" for p in host.ports if p.state == "open"]

    @staticmethod
    def _banners(host: NmapHost) -> list[str]:
        return [p.banner for p in host.ports if p.state == "open" and p.banner]

    def _exploit_phase(self, report: OrchestrationReport, host: NmapHost,
                       prof: ProfileResult, target: str, phase: str) -> bool:
        """한 단계를 익스플로잇 루프로 돈다. 공유 원장에 이력이 누적된다."""
        before = len(self._ledger.attempts())
        gate = Gate(self.guard, self.approver, hosts_map=self.hosts_map or {},
                    tool_available=self.is_tool_available)
        loop = ExploitLoop(gate, self.runner,
                           generators=self._build_generators(report, host, prof, target, phase),
                           ledger=self._ledger, probe=self.runner,
                           vault=self.vault, target=target,   # 플레이스홀더 확장·{t} 치환
                           # channel 은 비어 있다: 대상 안의 셸 채널이 아직 없다(미구현).
                           # 그래서 shell: 후보는 실행되지 않고 probe: 로만 접근을 증명한다.
                           attempt_timebox=self.exploit_attempt_timebox,
                           total_timebox=self.exploit_timebox,
                           max_rounds=self.exploit_max_rounds, audit=self.audit)
        self.audit.event("exploit_phase_start", phase=phase)
        result = loop.run()
        report.exploit_report = self._redact(result.report(known_surfaces=self._known_surfaces(host)))
        for a in self._ledger.attempts():      # 루프 관측에서 단서 수집(다음 단계용)
            self._clues.harvest(a.observed)

        for fh in result.footholds:
            if _is_capability(fh) and fh not in report.footholds:
                report.footholds.append(fh)
        # confirmed flag 시도 → FlagHit (출처 명령 보존)
        known_vals = {f.value for f in report.flags}
        for a in self._ledger.attempts():
            if a.verdict == "confirmed" and (a.foothold or "").startswith("flag:"):
                val = a.observed
                if val and val not in known_vals:
                    known_vals.add(val)
                    report.flags.append(_FlagHit(value=val, kind=a.foothold.split(":", 1)[1],
                                                 source=self._redact(a.commands[0]) if a.commands else phase,
                                                 provenance=a.provenance))
        self.audit.event("exploit_phase_end", phase=phase,
                         attempts=len(self._ledger.attempts()) - before,
                         footholds=report.footholds, flags=[f.kind for f in report.flags])
        return len(self._ledger.attempts()) > before

    def _run_vuln(self, report: OrchestrationReport, host: NmapHost, target: str) -> None:
        # 관측 코퍼스: 배너 + 스크립트 + enum/LLM 출력
        corpus_parts = list(host.hostscripts.values())
        banners: list[str] = []
        for p in host.ports:
            if p.state == "open":
                if p.banner:
                    banners.append(p.banner)
                    corpus_parts.append(p.banner)
                corpus_parts.extend(p.scripts.values())
        for f in report.enum_findings + report.llm_findings:
            if f.output:
                corpus_parts.append(f.output)
        hits = extract_vuln_ids("\n".join(corpus_parts))
        report.detected_cve = hits.cves
        report.detected_cwe = hits.cwes
        if self.vuln_kb is not None:
            report.vuln_matches = self.vuln_kb.match(banners, target)

    def _run_one_day(self, report: OrchestrationReport, host: NmapHost,
                     cves: list[str] | None = None) -> None:
        """Search only observed product/version or CVE metadata, never target identity."""
        try:
            report.one_day_leads = list(self.one_day_research.collect(host, cves))
            report.one_day_warnings = list(self.one_day_research.warnings)
        except Exception as e:
            report.one_day_warnings.append("1-day 검색 실패")
            self.audit.event("research_query", source="local", status="failed",
                             error=type(e).__name__)

    def _research_context(self, report: OrchestrationReport) -> list[str]:
        if self.one_day_research is None:
            return []
        if hasattr(self.one_day_research, "context_lines"):
            return self.one_day_research.context_lines()
        return [f"UNVERIFIED {r.get('id', '?')}: {r.get('title', '')}"
                for r in report.one_day_leads[:10]]

    def _attempt(self, report: OrchestrationReport, findings: list[EnumFinding],
                 cmd: str, phase: str = "enum") -> None:
        finding = EnumFinding(command=self._redact(cmd), phase=phase)
        findings.append(finding)
        self.audit.event("proposed", cmd=self._redact(cmd), phase=phase)

        binary = binary_of(cmd)
        if binary and not self.is_tool_available(binary):
            finding.note = f"건너뜀: '{binary}' 미설치"
            self.audit.event("skipped", cmd=self._redact(cmd), reason="tool-missing", binary=binary)
            return
        vrep: ValidationReport = validate(cmd)
        if not vrep.ok:
            finding.note = "검증 실패: " + "; ".join(str(i) for i in vrep.errors)
            self.audit.event("rejected", cmd=self._redact(cmd), stage="validate",
                             errors=[str(i) for i in vrep.errors])
            return
        try:
            sres: CommandScopeResult = self.guard.inspect_command(cmd, hosts_map=self.hosts_map)
        except ScopeViolation as e:
            finding.note = f"범위 오류: {e}"
            self.audit.event("rejected", cmd=self._redact(cmd), stage="scope", reason=str(e))
            return
        if not self.approver(cmd, vrep, sres):
            finding.note = "미승인(범위밖/사용자 거부)"
            self.audit.event("denied", cmd=self._redact(cmd), in_scope=sres.auto_allowed)
            return

        out = self.runner.run(cmd, timeout=180)
        finding.ran = out.launched
        if not out.launched:
            finding.note = f"실행 실패: {out.error}"
            self.audit.event("executed", cmd=self._redact(cmd), launched=False,
                             error=self._redact(out.error))
            return
        finding.output = self._redact(summarize_tool_output(cmd, out.stdout, out.stderr))
        self.audit.event("executed", cmd=self._redact(cmd), launched=True,
                         returncode=out.returncode, summary=finding.output)
        # 플래그 스캔 — 출력에서 user.txt/root.txt 획득. 열거 중 발견한 플래그는
        # 선행 Foothold(익스플로잇 루프 획득)가 있어야 genuine, 없으면 undemonstrated.
        earned = bool(self._ledger and
                      any(_is_capability(f) for f in self._ledger.footholds()))
        prov = _FLAG_GENUINE if earned else _FLAG_UNDEMONSTRATED
        for hit in scan_flags(cmd, out.stdout):
            if hit.value not in {f.value for f in report.flags}:
                hit.provenance = prov
                report.flags.append(hit)
                finding.note = (finding.note + " " if finding.note else "") + f"🚩 {hit.kind} flag"
                self.audit.event("flag_found", kind=hit.kind, value=hit.value,
                                 cmd=self._redact(cmd))
