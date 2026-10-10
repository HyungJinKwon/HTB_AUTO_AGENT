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

import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Callable

from . import command_fixer, diagnostics
from . import provenance as _prov
from .audit import NullAudit
from .command_validator import ValidationReport, shell_operators, validate
from .crack import scan_hashes as crack_scan
from .creds import CredentialVault
from .creds_harvest import harvest as harvest_creds
from .creds_harvest import is_safe_for_cmd
from .flag import FlagHit
from .flag import scan as scan_flags
from .hypotheses import HypothesisLedger, parse_id, strip_ledger_json
from .knowledge import KnowledgeBase
from .llm.router import LLMRouter
from .observation.compressor import profile_from_nmap
from .observation.parsers import NmapHost
from .observation.summarize import summarize_tool_output

# 렌더링은 report_view 로 분리 — 하위호환으로 수동제안 헬퍼를 여기서 재노출(테스트·외부 참조)
from .report_view import _compact_manual, _group_manual  # noqa: F401
from .scope_guard import CommandScopeResult, ScopeGuard, ScopeViolation
from .state import SessionState, StateStore, host_from_dict, host_to_dict
from .target_profiler import ProfileResult
from .tools.recon import Approver, ReconExecutor, ReconReport, auto_approve_in_scope
from .tools.runner import Runner, RunOutput
from .util import binary_of
from .variants import expand_variants, fragment_of
from .vuln import VulnKB, VulnMatch, extract_vuln_ids
from .world import WorldModel

# 모의해킹 진행 단계(순서대로). (key, 표시라벨)
PENTEST_PHASES: list[tuple[str, str]] = [
    ("enum", "열거 (Enumeration)"),
    ("access", "초기 침투 (Initial Access)"),
    ("privesc", "권한 상승 (Privilege Escalation)"),
    ("lateral", "측면 이동 (Lateral Movement)"),
]
_PHASE_LABEL = dict(PENTEST_PHASES)

# finding.output 1건당 보관 상한(바이트 아님 — 문자 길이). 요약기가 이미 줄이지만, 전용 분기가
# 길어질 수 있어 하드 실링을 둬 '보관 출력 총량 = 시도 수(예산 제한) × 이 값' 으로 명시적 bound.
_MAX_FINDING_OUTPUT = 4000
# 분석용 원본 출력 상한 — 요약보다 크게(버전/searchsploit 전체 행 보존) 두되 메모리는 bound.
_MAX_RAW_OUTPUT = 20000
# [S2] 고정점 반복 안전 상한 — 상태가 계속 자랄 때도 유한 종료를 보장하는 하드 실링이자
# 자율 모드 CLI 기본 스윕 수(main._run_target). 의존 체인 깊이 ~3보다 넉넉; 실제 종료는
# 보통 '성장 없음'/예산/시간이 먼저 끊는다. 명시 --max-sweeps 는 하드캡으로 존중된다.
_FIXED_POINT_CAP = 10

# 리다이렉트 출력(요약)에서 vhost 추출: "→ http://connected.htb/" → connected.htb
_REDIRECT_HOST_RE = re.compile(r"→\s*https?://([A-Za-z0-9.-]+?\.[A-Za-z]{2,})(?:[:/]|\s|$)")


@dataclass
class EnumFinding:
    command: str
    ran: bool = False
    note: str = ""
    output: str = ""        # 표시·저장용 요약(손실 가능) — summarize_tool_output 결과
    phase: str = "enum"
    skipped: bool = False   # 도구 미설치로 시도조차 안 함 — 예산(max_enum/max_llm)을 쓰지 않는다
    # 분석 전용 원본 출력(요약 전). 핑거프린트·searchsploit 매칭은 '요약'이 아니라 이 원본을
    # 봐야 한다 — 요약기(parse_http 등)의 엄격 정규식·상위 N개 캡으로 버전/매칭이 소실되던
    # 구조적 버그(capture≠evaluate) 교정용. 영속화하지 않음(세션 내 분석 한정).
    raw_output: str = ""


GATE_KEYS = ("proposed", "executed", "run_failed", "tool_missing", "rejected_validate",
             "rejected_scope", "denied_review", "denied_scope")


def _new_gate_stats() -> dict:
    return {k: 0 for k in GATE_KEYS}


@dataclass
class OrchestrationReport:
    target: str
    status: str = "pending"          # pending / done / escalate / interrupted
    recon: ReconReport | None = None
    host: NmapHost | None = None
    profile: ProfileResult | None = None
    world: "WorldModel | None" = None  # world.WorldModel — 구조화 상태(단일 상태원)
    analysis: str = ""                # LLM 분석가(B3) — 가설·공격경로·다음집중·확신도
    # 가설 기록(계획 원장) — 분석가가 갱신, 명령 생성은 '지금 할 일 1개'에 집중, 결과로 상태 갱신
    plan: HypothesisLedger = field(default_factory=HypothesisLedger)
    phase_status: dict = field(default_factory=dict)   # A2 단계 게이팅 상태(phase→상태)
    # 3관문 결과 집계(열거·LLM 명령 기준, 정찰 포트스캔 제외) — 리포트·대시보드용
    gate_stats: dict = field(default_factory=_new_gate_stats)
    enum_findings: list[EnumFinding] = field(default_factory=list)
    llm_findings: list[EnumFinding] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    detected_cve: list[str] = field(default_factory=list)
    detected_cwe: list[str] = field(default_factory=list)
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)
    flag_kind: str = "boot2root"     # boot2root(user/root) | single(CTF flag)
    enriched: list = field(default_factory=list)   # list[enrich.CveInfo]
    # 자동 준비된 리버스쉘 페이로드(공격자 IP 확보 시 자동 생성 — 생성만, 실행 안 함)
    revshells: list = field(default_factory=list)   # list[revshell.RevShell]
    revshell_lhost: str = ""
    revshell_lport: int = 0
    # 자동 준비된 AWS/S3 열거(호스트명/도메인 확보 시 — 생성만, AWS 는 범위 밖·실행 안 함)
    cloud_candidates: list = field(default_factory=list)   # list[str] 버킷 후보
    cloud_checks: list = field(default_factory=list)       # list[cloud.CloudCheck]
    # 자동 준비된 권한상승 플레이북(OS 식별 시 — 생성만, 대상 셸에서 사용자 실행)
    privesc_steps: list = field(default_factory=list)      # list[privesc.PrivescStep]
    privesc_cve_candidates: list = field(default_factory=list)  # list[str]
    privesc_vectors: list = field(default_factory=list)    # list[privesc_analyze.PrivescVector]
    # 자동 준비된 해시 크래킹 작업(출력/볼트에서 해시 수집 시 — 생성만, 사용자 실행)
    crack_jobs: list = field(default_factory=list)         # list[crack.CrackJob]
    # 자율 지식 획득(모르는 기술 → 권위 출처에서 자동 학습, P1 유지)
    acquired_knowledge: list = field(default_factory=list)  # "용어 → 주제 (출처)"
    knowledge_gaps: list = field(default_factory=list)      # 미해석 공백(수동 조사 필요)
    # 지식 기반 현황(번들 시드·승격·공유 동기화) — kb_sync.knowledge_summary, main 이 채움
    knowledge: dict = field(default_factory=dict)
    # 실패 진단(사람 확인용) — (command, FailureDiagnosis) 목록. 자동 재공격 아님
    blockers: list = field(default_factory=list)
    # 플래그 출처 검증(실행 트레이스 기반) — list[provenance.FlagProvenance]
    flag_provenance: list = field(default_factory=list)
    # 적대적 재검증(skeptic) — 독립 재현 기반 확신도. {(kind,value): verify.Confidence}
    flag_confidence: dict = field(default_factory=dict)
    goal_reached: bool = False        # 신뢰 가능한 플래그로 목표 달성 → 남은 단계 조기 종료
    timed_out: bool = False           # 시간 예산 소진 → 남은 단계 조기 종료(상태 저장)
    cost_capped: bool = False         # LLM 비용 상한 도달 → 이후 규칙 기반으로만 진행
    elapsed_sec: float = 0.0          # 이번 실행 경과 시간(초)
    # LLM 라우팅 집계(하이브리드일 때 main 이 채움): 로컬/강력/폴백/거절/빈응답/오류/미응답 + 차단 백엔드
    llm_routing: dict = field(default_factory=dict)
    message: str = ""

    @property
    def user_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "user"), None)

    @property
    def root_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "root"), None)

    def summary(self) -> str:
        from . import report_view
        return report_view.render_summary(self)

    def glance(self) -> str:
        """맨 끝 '한눈에 보기' — report_view.render_glance 로 위임(렌더링은 report_view)."""
        from . import report_view
        return report_view.render_glance(self)


class Orchestrator:
    def __init__(self, guard: ScopeGuard, runner: Runner, kb: KnowledgeBase,
                 approver: Approver = auto_approve_in_scope,
                 hosts_map: dict[str, str] | None = None,
                 max_enum: int = 6,
                 recon_max_attempts: int = 4,
                 max_rounds: int = 2,
                 max_sweeps: int = 2,
                 max_variants: int = 1,
                 llm_router: LLMRouter | None = None,
                 max_llm: int = 5,
                 vuln_kb: VulnKB | None = None,
                 vault: CredentialVault | None = None,
                 state_store: StateStore | None = None,
                 resume: bool = False,
                 audit=None,
                 phases: list[tuple[str, str]] | None = None,
                 flag_kind: str = "boot2root",
                 flag_prefixes: tuple[str, ...] = (),
                 enricher=None,
                 platform_name: str = "Hack The Box",
                 category: str = "",
                 revshell_port: int = 4444,
                 variant_stats=None,
                 max_parallel: int = 1,
                 time_budget: float = 0.0,
                 max_cost: float = 0.0,
                 observer: Callable[[str], str] | None = None,
                 quiet: bool = False,
                 replan_after: int = 2,
                 clock=None,
                 learner=None,
                 learn_gaps: bool = False,
                 max_gap_learn: int = 6,
                 web_learner=None,
                 is_tool_available: Callable[[str], bool] | None = None,
                 recon_extra_ports: "list[int] | None" = None,
                 fix_commands: bool = True,
                 dry_run: bool = False,
                 exploit_exec: bool = False,
                 auto_poc: bool = False,
                 poc_commands: "list[str] | None" = None,
                 workspace=None):
        self.guard = guard
        self.runner = runner
        self.kb = kb
        self.approver = approver
        self.hosts_map = hosts_map
        self.max_enum = max_enum
        self.recon_max_attempts = recon_max_attempts
        self.max_rounds = max(1, max_rounds)
        self.max_sweeps = max(1, max_sweeps)
        self.max_variants = max(1, max_variants)
        self.llm_router = llm_router
        self.max_llm = max_llm
        self.vuln_kb = vuln_kb
        self.vault = vault
        self.state_store = state_store
        self.resume = resume
        self.audit = audit or NullAudit()
        self.phases = phases or PENTEST_PHASES
        self.flag_kind = flag_kind
        self.flag_prefixes = flag_prefixes
        self.platform_name = platform_name
        self.category = category
        self.revshell_port = revshell_port
        self.variant_stats = variant_stats   # 실행 결과 기반 변형 학습(없으면 미학습)
        self.max_parallel = max(1, max_parallel)   # 열거 동시 실행 수(1=순차)
        self.time_budget = max(0.0, time_budget)   # 해커톤 시간 예산(분, 0=무제한)
        self.max_cost = max(0.0, max_cost)         # LLM 누적 추정 비용 상한(USD, 0=무제한)
        # 사람 관찰 입력(선택): 건너뛴 명령 대신 사람이 직접 확인한 내용을 받아 기록한다
        self.observer = observer
        self.quiet = quiet   # 화면 경고 끔(벤치 등 비대화형) — 비고·감사 로그에는 그대로 기록
        # 같은 가설에서 기대 신호가 연속 N회 어긋나면 '막힘' → 분석가(강력 모델) 재계획
        self.replan_after = max(1, replan_after)
        self._clock = clock or time.monotonic      # 테스트 주입용(단조 시계)
        self.enricher = enricher
        # 자율 지식 획득 — 모르는 기술을 권위 출처에서 자동 학습(learner 주입 시)
        self.learner = learner
        self.learn_gaps = learn_gaps
        self.max_gap_learn = max(0, max_gap_learn)
        self.web_learner = web_learner   # 인터넷 검색 학습(HTB 라이트업 가드) — 미해석 공백용
        self._acquired_topics: set[str] = set()   # 세션 내 중복 학습 방지
        # 도구 설치 여부 판단(주입 가능 — 테스트에서 대체)
        # 샌드박스 실행기는 컨테이너 안의 도구 설치 여부를 직접 답한다(has_tool)
        self.is_tool_available = (is_tool_available or getattr(runner, "has_tool", None)
                                  or (lambda b: shutil.which(b) is not None))
        # 작업공간(첨부파일 + LLM 이 쓴 스크립트). 파일 쓰기 액션은 contained 실행기에서만 실행.
        self.workspace = workspace
        # nmap 미설치 시 소켓 폴백에 추가로 확인할 포트(라이브 벤치가 아는 서비스 포트)
        self.recon_extra_ports = [int(p) for p in (recon_extra_ports or [])]
        # Results Verifier: 범위 밖 명령의 타겟 자동 교정 복구(AutoPentester). 끄려면 False.
        self.fix_commands = fix_commands
        # 계획 미리보기: 정찰·분석은 하되 제안된 enum/LLM/파일 명령은 '실행하지 않고' 보여만 준다.
        self.dry_run = dry_run
        self.exploit_exec = exploit_exec
        self.auto_poc = auto_poc
        self._exploit_looked_up: set[str] = set()   # 제품별 공개 익스 조회 1회 가드
        self._version_probed: set[str] = set()       # 제품별 버전 노출 프로브 1회 가드
        self._web_secret_probed: set[str] = set()     # 웹 노출 비밀/백업 열거 1회 가드(베이스별)
        self._web_fp_probed: set[str] = set()          # vhost 결정적 핑거프린트 1회 가드
        self.poc_commands = poc_commands or []

    def run(self) -> OrchestrationReport:
        # 경과 시간은 정찰부터 포함, 마감 확인은 스윕 루프에서(정찰은 유한 폴백으로 별도 관리)
        self._start = self._clock()
        self._deadline = (self._start + self.time_budget * 60) if self.time_budget else None
        if self.guard.bound_target is None and self.guard.bound_host is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target or self.guard.bound_host)
        report = OrchestrationReport(target=target, flag_kind=self.flag_kind)
        report.plan.replan_after = self.replan_after
        # 구조화 상태(월드 모델) — 파이프라인·LLM·리포트의 단일 상태원
        self.world = WorldModel(target=target,
                                hostname=(self.hosts_map or {}).get(target, ""))
        report.world = self.world
        if self.vault is not None:
            for c in self.vault.creds:
                sec = c.password or c.nt_hash or ""
                self.world.add_cred(f"{c.username}:{sec}" if sec else c.username)
        self._found_hashes: list[str] = []   # 실행 원시출력에서 수집한 크래킹 대상 해시
        self._vhost_seen: set[str] = set()   # 리다이렉트에서 자동 등록한 vhost(중복 방지)
        self.audit.event("session_start", target=target, resume=self.resume,
                         ranges=[str(n) for n in self.guard.allowed_target_cidrs])

        # 재개: 저장된 상태에 포트가 있으면 RECON 을 건너뛰고 재사용
        prior: SessionState | None = None
        host = None
        seen_cmds: set[str] = set()
        if self.resume and self.state_store and self.state_store.exists(target):
            prior = self.state_store.load(target)
            if prior and prior.host:
                host = host_from_dict(prior.host)
                report.message = "(재개: 저장된 RECON 재사용 — 재스캔 생략) "
            if prior:
                self._restore(report, prior, seen_cmds)
        # 예산은 '이번 실행' 기준(재개로 복원한 이전 결과는 예산을 쓰지 않음)
        self._enum_base = len(report.enum_findings)
        self._llm_base = len(report.llm_findings)

        # ── PHASE 1: RECON (유한 폴백) — 재개로 host 확보 시 생략 ──
        # 정찰(nmap)은 스윕 루프의 KeyboardInterrupt 처리 '밖'에서 돌므로, 가장 흔한
        # 중단 지점(첫 스캔 중 Ctrl+C)이 raw 트레이스백 + 상태 유실로 이어졌다. 여기서
        # 받아 상태를 저장하고 정상 종료한다(--resume 약속 유지 — 품질검수 MED).
        if host is None:
            try:
                recon = ReconExecutor(self.guard, self.runner, self.approver,
                                      max_attempts=self.recon_max_attempts,
                                      hosts_map=self.hosts_map,
                                      is_tool_available=self.is_tool_available,
                                      extra_ports=self.recon_extra_ports).run_portscan()
            except KeyboardInterrupt:
                report.status = "interrupted"
                report.elapsed_sec = round(self._clock() - self._start, 1)
                report.message += "사용자 중단(정찰 단계) — 진행 상태 저장(--resume 으로 이어서 진행). "
                self.audit.event("interrupted", phase="recon")
                self._persist(report, prior)
                self.audit.event("session_end", status=report.status, message=report.message)
                return report
            report.recon = recon
            host = recon.host
        report.host = host
        self.audit.event("recon", status=(report.recon.status if report.recon else "resumed"),
                         open_ports=host.open_ports if host else [])
        if (host is None or not host.open_ports) and self.workspace is not None \
                and self.workspace.imported:
            # 첨부파일만 있는 문제(rev/crypto/forensic 등): 열린 포트 없이 파일 분석으로 진행
            host = host or NmapHost(address=target, state="unknown")
            report.host = host
            report.message += "(열린 포트 없음 — 첨부파일 분석으로 진행) "
            self.audit.event("offline_files", files=self.workspace.imported[:20])
        if host is None or (not host.open_ports and not (
                self.workspace is not None and self.workspace.imported)):
            report.status = "escalate"
            report.message += "열린 포트 미확보 — 다음 단계 불가. 사람 개입 필요."
            self._persist(report, prior)
            self.audit.event("session_end", status=report.status, message=report.message)
            return report

        # ── PHASE 2: PROFILE ──
        prof = profile_from_nmap(host)
        report.profile = prof
        self.world.set_profile(host, prof)   # 호스트/서비스/OS 상태 반영
        self.audit.event("profile", os=prof.os_class.value, confidence=prof.confidence,
                         is_dc=prof.is_domain_controller)

        # ── PHASE 3: 모의해킹 단계 '순서대로' 진행 (유한 반복·재진입 스윕) ──
        # enum → access → privesc → lateral 순. 각 단계는 KB(해당 phase)+LLM 적응
        # 라운드를 돌린다. 한 스윕(전 단계 1회 통과) 뒤 '월드 상태가 성장'하면
        # (새 관측·크리덴셜·서비스로 이전 단계가 다시 유효해지면) 다음 스윕을 돈다.
        # 전역 상한(max_enum·max_llm)·명령 중복제거(seen_cmds)·상태정체 조기종료로 유한.
        phases_run: list[str] = []
        sweeps_run = 0
        self._analysis_fp: tuple | None = None
        interrupted = False
        try:
            # [S2] 고정점 반복: 상태가 자라는 한 계속 돌려 의존 체인(제품→버전→익스조회 등)이
            # 완주한다. 종료의 1차 기준은 '성장 없음'(_world_fingerprint 불변) — 아래 조기종료.
            # max_sweeps 는 안전 상한(폭주 방지)이며 명시 지정은 하드캡으로 존중한다. 실전 기본은
            # 체인 완주가 가능하도록 CLI 에서 높게(_FIXED_POINT_CAP) 잡는다. 전역 예산·시간도 유한 보장.
            sweep_cap = self.max_sweeps
            while sweeps_run < sweep_cap:
                if self._goal_reached(report) or self._time_up():
                    break
                before_fp = self._world_fingerprint(report)
                # 지금까지의 출력에서 취약점(CVE/CWE·버전 매칭)을 먼저 반영 — 학습·분석·
                # 명령 생성이 '확인 취약점'을 보고 판단하도록(이전엔 루프가 끝난 뒤에야 계산)
                self._run_vuln(report, host, target)
                # [S1] 의존 순서대로 배치 — 생산자(제품/버전 식별)를 소비자(버전프로브·익스조회)
                # 보다 먼저 돌린다. 과거엔 web_fingerprint 가 소비자 뒤에 있어 제품이 '한 스윕 늦게'
                # 반영되던 결정성 버그. 결정적 핑거프린트: vhost 리다이렉트를 따라가 제품/버전 확정.
                self._web_fingerprint_stage(report, host)
                # 버전 노출 능동 프로브: 제품은 식별됐는데 버전이 미상이면, 문서화된 제품별
                # 버전 노출 경로를 무해한 GET 으로 긁어 버전을 집어낸다(제품당 1회). 익스 아님.
                self._version_probe_stage(report, host)
                # 3단계 기반: 핑거프린트된 웹앱 제품에 맞는 공개 익스 '조회'(searchsploit)를
                # 게이트로 올린다(제품당 1회). 조회·무해 — 익스 실행 아님. 결과는 다음 분석에 되먹임.
                self._exploit_lookup_stage(report, host)
                # 발판 전 자격 수확: 웹 노출 비밀/백업 파일을 읽기전용 GET 으로 열거(호스트당 1회).
                # 무해 — 본문에서 자격이 나오면 _harvest_creds 가 world 에 반영 → ①(b) 인증 PoC 폐루프.
                self._web_secret_stage(report, host)
                # 자율 지식 획득: 관측된 기술 중 '모르는 것'을 권위 출처에서 자동 학습해
                # KB 에 즉시 반영한다(이후 분석가·명령생성이 바로 활용). P1 유지.
                self._acquire_knowledge(report, host, prof)
                for key, label in self.phases:
                    if self._time_up():
                        report.phase_status.setdefault(key, "생략(시간 예산 소진)")
                        continue
                    if self._goal_reached(report):
                        report.phase_status.setdefault(key, "생략(목표 달성)")
                        continue
                    # A2 단계 게이팅: 전제(권한레벨/크리덴셜) 미충족 단계는 KB 가이드(수동
                    # 제안)는 남기되 투기적 LLM 라운드는 건너뛴다(상태가 자라면 다음 스윕서 활성).
                    met, reason = self._prereq_met(key)
                    # B3 분석가: 이 단계의 명령 생성 직전에, 마지막 분석 이후 상태가 자랐을
                    # 때만 다시 판단한다(앞 단계 결과·새 크리덴셜·취약점을 계획에 반영).
                    use_llm = (met and self.llm_router is not None
                               and not self._cost_capped(report))
                    if use_llm:
                        self._refresh_analysis(report, prof, host, target)
                    phase_before = len(report.enum_findings) + len(report.llm_findings)
                    for _rnd in range(self.max_rounds):
                        added = self._enum_round(
                            report, host, prof, target, seen_cmds,
                            self.max_enum - self._spent(report.enum_findings, self._enum_base),
                            key)
                        if (use_llm and not self._goal_reached(report)
                                and not self._cost_capped(report)):
                            added += self._llm_round(
                                report, host, prof, target, seen_cmds,
                                self.max_llm - self._spent(report.llm_findings, self._llm_base),
                                key)
                        if added == 0 or self._goal_reached(report) or self._time_up():
                            break
                    grew = len(report.enum_findings) + len(report.llm_findings) > phase_before
                    if grew and key not in phases_run:
                        phases_run.append(key)
                    # 한 번이라도 '진행'한 단계는 이후 스윕에서 새 명령이 없어도 '진행' 유지
                    if report.phase_status.get(key) != "진행":
                        report.phase_status[key] = ("대기(" + reason + ")" if not met
                                                    else ("진행" if grew else "점검함"))
                    self._run_vuln(report, host, target)   # 다음 단계가 새 취약점을 보도록
                # [S1] enum 단계가 vhost 를 등록하거나 웹 본문을 받아 제품이 '이번 스윕에'
                # 식별됐을 수 있다 → 소비자(핑거프린트·버전프로브·익스조회)를 한 번 더 돌려
                # 같은 스윕에 반영(다음 스윕까지 밀리지 않게). 전부 멱등 — 바뀐 게 없으면 no-op.
                self._web_fingerprint_stage(report, host)
                self._version_probe_stage(report, host)
                self._exploit_lookup_stage(report, host)
                sweeps_run += 1
                # 무인 자율 진행 투명성(heartbeat): 스윕마다 1줄 요약 — 폭주 감시·발표 시연용
                if not self.quiet:
                    from . import ui
                    fl = f"user={'O' if report.user_flag else 'X'} root={'O' if report.root_flag else 'X'}"
                    spent = float(getattr(self.llm_router, "total_cost", 0.0) or 0.0)
                    print("  " + ui.dim(
                        f"⏱ 스윕 {sweeps_run}/{sweep_cap} · 경과 {self._clock() - self._start:.0f}초 · "
                        f"enum {len(report.enum_findings)} · LLM {len(report.llm_findings)} · "
                        f"플래그 {fl} · 비용 ${spent:.3f}"))
                # 이번 스윕에서 상태가 더 자라지 않았으면(새 관측·예산 소진) 조기 종료 — 유한
                if self._world_fingerprint(report) == before_fp:
                    break
        except KeyboardInterrupt:
            # 사용자 중단(Ctrl+C): 지금까지의 결과를 저장해 --resume 으로 이어갈 수 있게 한다
            interrupted = True
            self.audit.event("interrupted", sweeps=sweeps_run)
        report.timed_out = self._time_up()
        report.elapsed_sec = round(self._clock() - self._start, 1)
        if report.timed_out:
            # 시간 예산 소진도 중단과 같은 경로: 남은 단계 생략, 상태 저장, 네트워크 수집 생략
            interrupted = True
            self.audit.event("timed_out", budget_min=self.time_budget,
                             elapsed_sec=report.elapsed_sec, sweeps=sweeps_run)

        # ── PHASE 3.7: VULN (CVE/CWE 탐지 + 매핑) — 최종 출력까지 반영 ──
        self._run_vuln(report, host, target)

        # NSE 취약점 스크립트 보수적 제안(실행은 무겁고 길어 수동 제안으로)
        if host.open_ports:
            ports = ",".join(str(p) for p in host.open_ports)
            report.manual_suggestions.append(
                f"nmap -sV --script vuln -p {ports} {target}   # NSE 취약점 스캔(수동)")

        # ── CVE/CWE 레퍼런스 자동 수집(공식 출처, best-effort) ──
        if self.enricher is not None and not interrupted:   # 중단 시 네트워크 수집 생략
            all_cves = list(report.detected_cve)
            for m in report.vuln_matches:
                all_cves += m.cve
            if all_cves:
                try:
                    report.enriched = self.enricher.enrich(all_cves, report.detected_cwe)
                    if report.enriched:
                        self.audit.event("enriched",
                                         cves=[e.id for e in report.enriched])
                except Exception as e:   # noqa: BLE001 — 수집 실패는 진행 방해 금지
                    self.audit.event("enrich_error", error=str(e))
        # 모든 스윕·enum 종료 시점에서 ⭐ 버전매칭 PoC 숏리스트를 최종 재평가 — 버전이 enum
        # 단계에서 늦게 확정돼 조기 평가가 '매칭 없음'으로 굳는 문제 교정. auto-poc 큐잉도 여기서
        # 확정(아래 실행 스테이지가 소비). exploit-exec 와 무관하게 제안은 항상 최신화. 생성 전용.
        if not interrupted:
            self._refresh_exploit_shortlist(report, host)
        # PHASE 3.9 직전: PoC 실행(3단계) → 웹 RCE 발판 → exploit-exec 발판(1단계)
        if self.exploit_exec and not interrupted:
            self._exploit_run_stage(report, host)     # 3단계: PoC 실행 → 자격
            self._foothold_stage(report, host)        # 웹 RCE 발판 → 자격수확 → 플래그
            self._exploit_exec_stage(report, host)    # 1단계: SSH 자격 → 플래그 → privesc

        # ── PHASE 3.9: 리버스쉘 자동 준비 (공격자 IP 확보 시) ──
        self._prepare_revshells(report)

        # ── PHASE 3.95: AWS/S3 열거 자동 준비 (호스트명/도메인 확보 시) ──
        # 버킷 후보·비인증 점검을 자동 생성. AWS 엔드포인트는 타겟 범위 밖이라
        # 실행하지 않고 준비만 한다(리버스쉘과 동일한 '생성 전용' 안전 경계).
        self._prepare_cloud(report)

        # ── PHASE 3.96: 권한상승 플레이북 자동 준비 (OS 식별 시) ──
        # OS 에 맞는 포스트-익스플로잇 권한상승 열거·점검 체크리스트를 자동 생성.
        # 대상 셸 안에서 실행하는 명령이라 에이전트는 준비만(생성 전용) 한다.
        self._prepare_privesc(report, prof)

        # ── PHASE 3.97: 해시 크래킹 자동 준비 (출력/볼트에서 해시 수집 시) ──
        # 캡처된 해시를 식별해 john/hashcat 명령을 자동 생성. 크래킹은 무겁고
        # 워드리스트가 필요해 에이전트는 준비만(생성 전용) 한다.
        self._prepare_crack(report)

        # 적대적 재검증(skeptic): 포착된 플래그를 '독립 재현' 관점에서 재채점해 확신도를
        # 보고에 싣고, 단일 출처면 독립 재읽기 명령을 수동 제안으로 남긴다(생성 전용 — 실행 아님).
        self._assess_flags(report)

        # ── PHASE 4: REPORT ──
        report.status = "interrupted" if interrupted else "done"
        if report.timed_out:
            report.message += (f"시간 예산 {self.time_budget:g}분 소진(경과 {report.elapsed_sec:.0f}초) "
                               "— 남은 단계 생략, 진행 상태 저장(--resume 으로 이어서 진행). ")
        elif interrupted:
            report.message += "사용자 중단 — 진행 상태 저장(--resume 으로 이어서 진행). "
        if report.cost_capped:
            report.message += (f"LLM 비용 상한 ${self.max_cost:g} 도달 — 이후 규칙 기반으로 진행. ")
        elif self._goal_reached(report):
            report.goal_reached = True
            report.message += "목표 달성 — 남은 단계 조기 종료. "
        flag_state = f"user={'O' if report.user_flag else 'X'} root={'O' if report.root_flag else 'X'}"
        report.message += (f"OS={prof.os_class.value}({prof.tag}), "
                           f"스윕 {sweeps_run}회, "
                           f"진행단계 {'→'.join(phases_run) or '없음'}, "
                           f"KB enum {len(report.enum_findings)}건, "
                           f"LLM {len(report.llm_findings)}건, 플래그[{flag_state}]")
        self._persist(report, prior)
        self.audit.event("vuln", cve=report.detected_cve, cwe=report.detected_cwe,
                         matches=[m.name for m in report.vuln_matches])
        self.audit.event("session_end", status=report.status, message=report.message)
        return report

    def _restore(self, report: OrchestrationReport, prior: SessionState,
                 seen: set[str]) -> None:
        """재개: 이전 실행에서 '실제로 실행된' 명령과 결과·플래그·수동 제안을 복원한다.
        실행된 명령은 seen 에 넣어 다시 돌리지 않고(중복 공격·시간 낭비 방지), 복원한 결과는
        분석·명령 생성의 맥락이 되며 저장 시 이력이 사라지지 않는다. 실행되지 않은 명령
        (거부·미설치·미승인)은 복원하지 않아 이번 실행에서 다시 판단된다."""
        for src, dst in ((prior.enum_findings, report.enum_findings),
                         (prior.llm_findings, report.llm_findings)):
            for d in src or []:
                cmd = (d or {}).get("command", "")
                if not cmd or not d.get("ran") or cmd in seen:
                    continue
                seen.add(cmd)
                dst.append(EnumFinding(command=cmd, ran=True, note=d.get("note", ""),
                                       output=d.get("output", ""),
                                       phase=d.get("phase") or "enum"))
        for fd in prior.flags or []:
            value, kind = (fd or {}).get("value", ""), fd.get("kind", "")
            if not value or value in {f.value for f in report.flags}:
                continue
            report.flags.append(FlagHit(value, kind, fd.get("source", "")))
            if fd.get("verdict"):
                # 첫 실행에서 정한 출처 판정을 그대로 복원한다. 재계산하면 in_external
                # (라이트업·학습 유래)·오프라인 첨부 보정이 사라져, 정직성 표시가 조용히
                # 바뀌고(goal 상태가 뒤집혀) provenance 기능이 resume 에서 무력화된다(MED-2).
                report.flag_provenance.append(_prov.FlagProvenance(
                    kind, value, fd.get("prov_command", ""), fd.get("phase", ""),
                    fd["verdict"], fd.get("reason", "")))
            else:   # 구버전 상태(verdict 미저장) 호환 — 보수적 재계산
                report.flag_provenance.append(
                    _prov.classify(kind, value, fd.get("source", "")))
            if self.world is not None:
                self.world.add_flag(kind, value)
        for m in prior.manual_suggestions or []:
            if m not in report.manual_suggestions:
                report.manual_suggestions.append(m)
        # 계획 이어가기: 가설 기록·분석을 복원해 재개 후 첫 분석이 '갱신'이 되게(처음부터 다시 X)
        if prior.plan:
            report.plan = HypothesisLedger.from_dict(prior.plan)
            report.plan.replan_after = self.replan_after
        if prior.analysis and not report.analysis:
            report.analysis = prior.analysis
        if report.enum_findings or report.llm_findings or report.flags:
            self.audit.event("resumed", findings=len(report.enum_findings)
                             + len(report.llm_findings), flags=len(report.flags))

    @staticmethod
    def _spent(findings: list[EnumFinding], base: int = 0) -> int:
        """이번 실행에서 예산을 쓴 시도 수 — 도구 미설치로 건너뛴 명령은 제외."""
        return sum(1 for f in findings[base:] if not f.skipped)

    def _tool_ok(self, cmd: str) -> bool:
        """명령의 바이너리가 설치돼 실제 실행 가능한지(예산 소비·시도 집계를 '설치된 도구'로 한정)."""
        binary = binary_of(cmd)
        return not binary or self.is_tool_available(binary)

    def _goal_reached(self, report: OrchestrationReport) -> bool:
        """목표 달성 여부 — 달성하면 남은 공격 단계를 돌리지 않는다(불필요한 대상 상호작용·
        예산 낭비 방지). 대상 상호작용 출력에서 나온(provenance=exploit-derived) 플래그만
        인정해, 로컬 명령 출력의 미끼/예시 문자열로 조기 종료하지 않는다.
          · single(Jeopardy): 플래그 1개(접두 지정 시 그 접두)
          · boot2root(HTB) : user + root 둘 다"""
        trusted = {(p.kind, p.value) for p in report.flag_provenance
                   if p.verdict == "exploit-derived"}
        hits = [f for f in report.flags if (f.kind, f.value) in trusted]
        if self.flag_kind == "single":
            pref = tuple(p.lower() for p in self.flag_prefixes)
            return any(not pref or f.value.split("{", 1)[0].lower() in pref for f in hits)
        kinds = {f.kind for f in hits}
        return "user" in kinds and "root" in kinds

    def _assess_flags(self, report: OrchestrationReport) -> None:
        """포착된 플래그를 '독립 재현' 관점에서 재채점(verify.assess)해 report.flag_confidence
        에 싣는다. 공략 유래지만 단일 출처면, 다른 방법으로 재읽기하는 독립 명령을 수동 제안에
        1회 남겨 사람이 재확인하도록 한다(생성 전용 — 실행은 3관문). 신뢰 판정을 바꾸지 않는다."""
        from . import verify
        for f in report.flags:
            conf = verify.assess(f.kind, f.value, report.flag_provenance)
            report.flag_confidence[(f.kind, f.value)] = conf
            if conf.level == "single-source" and conf.sources:
                rereads = verify.reread_commands(conf.sources[0])
                if rereads:
                    report.manual_suggestions.append(
                        f"# 🔎 재검증(단일 출처 플래그 {f.kind}) — 같은 값을 '다른 방법'으로 "
                        f"재읽기해 재현되면 신뢰도 상승(권한 확인 대상 전용):\n"
                        + "\n".join(f"#   - {c}" for c in rereads))

    def _cost_capped(self, report: OrchestrationReport) -> bool:
        """LLM 누적 추정 비용이 상한에 도달했으면 True(처음 도달 시 1회 기록). 이후엔 규칙 기반만."""
        if report.cost_capped:
            return True
        if not self.max_cost or self.llm_router is None:
            return False
        spent = float(getattr(self.llm_router, "total_cost", 0.0) or 0.0)
        if spent < self.max_cost:
            return False
        report.cost_capped = True
        self.audit.event("cost_capped", max_cost=self.max_cost, spent=round(spent, 4))
        return True

    @staticmethod
    def _failure_context(report: OrchestrationReport, limit: int = 6) -> list[str]:
        """최근 실패 진단을 LLM 맥락용 한 줄씩으로(논문 공통: 실패를 계획에 되먹임).
        '대상 응답'(404/403 등)은 경로 판단 근거, '환경/도구'는 근거 아님을 함께 표시한다."""
        out: list[str] = []
        for cmd, d in (getattr(report, "blockers", []) or [])[-limit:]:
            basis = "경로 판단 근거" if d.is_target else "환경 문제 — 경로 포기 근거 아님"
            out.append(f"{cmd[:120]} → [{d.kind}] {d.label} ({basis})")
        return out

    def _time_up(self) -> bool:
        """해커톤 시간 예산 마감 도달 여부(예산 0=무제한이면 항상 False)."""
        return self._deadline is not None and self._clock() >= self._deadline

    def _refresh_analysis(self, report: OrchestrationReport, prof: ProfileResult,
                          host: NmapHost, target: str) -> None:
        """'의미 있는 변화'가 있을 때만 분석가를 다시 부른다 — 계획을 처음부터 다시 세우지
        않고 이어서 갱신한다. 명령이 하나 더 실행된 것만으로는 다시 부르지 않는다(비용·방향 유지).
        변화: 새 크리덴셜·서비스·수집물·취약점·권한·플래그, 가설 확인/기각, 가설 막힘."""
        if self._plan_fingerprint(report) == self._analysis_fp:
            return
        self._run_analyst(report, prof, host, target)
        # 분석가가 방금 갱신한 가설 기록까지 포함해 기준점을 잡는다(자기 갱신으로 재호출 방지)
        self._analysis_fp = self._plan_fingerprint(report)

    def _plan_fingerprint(self, report: OrchestrationReport) -> tuple:
        """재계획 판정용 지문 — 가설 기록이 있으면 실행 건수는 넣지 않는다(명령 하나마다
        재계획하지 않도록; 실패는 가설의 '막힘'으로 반영). 분석가가 가설을 주지 못해 기록이
        비었으면 예전처럼 실행 결과가 늘 때마다 다시 판단한다(실패 되먹임 유지)."""
        w = self.world
        growth: tuple = (() if report.plan
                         else (len(report.enum_findings), len(report.llm_findings),
                               len(report.blockers)))
        return growth + (
            len(w.creds) if w else 0,
            len(w.services) if w else 0,
            len(w.loot) if w else 0,
            len(w.learned) if w else 0,   # 자율학습 성장도 '상태 성장'으로 인정(다음 스윕 유도)
            len(w.proven_vulns) if w else 0,
            w.access_level if w else "none",
            # 웹앱 식별·vhost 등록도 '상태 성장'으로 인정 — 이들만 자란 스윕이 '정체'로 오판돼
            # 조기 종료되면, 그걸 소비하는 다음 스테이지(버전프로브·익스조회)가 영영 안 돌던
            # 결정성 버그 교정(S1).
            w.web_product if w else "",
            w.web_version if w else "",
            len(self.hosts_map or {}),
            len(report.flags),
            len(report.detected_cve),
            len(report.vuln_matches),
            report.plan.signature(),
        )

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
        def fin(f):
            return {"command": f.command, "ran": f.ran, "note": f.note,
                    "output": f.output, "phase": f.phase}
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
            st.credentials = self.vault.to_list()
        if report.flags:
            provmap = {(p.kind, p.value): p for p in report.flag_provenance}

            def _flag_dict(f):
                d = {"value": f.value, "kind": f.kind, "source": f.source}
                p = provmap.get((f.kind, f.value))
                if p is not None:   # 출처 판정을 보존(resume 시 재계산하지 않도록 — MED-2)
                    d.update(verdict=p.verdict, prov_command=p.command,
                             phase=p.phase, reason=p.reason)
                return d
            st.flags = [_flag_dict(f) for f in report.flags]
        if report.plan:
            st.plan = report.plan.to_dict()
        if report.analysis:
            st.analysis = report.analysis
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
        # 1) 실행 후보를 '서비스(태그)별 버킷'으로 모은다 — 예산은 아직 쓰지 않는다.
        #    (한 서비스가 예산을 독식하지 않도록, 2)에서 서비스 round-robin 으로 분배해 탐색 폭을 넓힌다)
        buckets: dict[str, list[tuple[str, str]]] = {}
        order: list[str] = []   # 버킷 최초 등장 순서(결정적 — recs 는 점수순 정렬됨)
        for rec in recs:
            key = rec.tags[0] if rec.tags else "기타"   # 서비스/카테고리 키(web·smb·ftp·ad…)
            for tmpl in rec.suggestions:
                for cmd, runnable in self._expand(tmpl, target):
                    if not runnable:
                        if cmd in seen:
                            continue
                        seen.add(cmd)
                        report.manual_suggestions.append(
                            cmd + f"   # [{_PHASE_LABEL.get(phase, phase)}] {rec.rule_name}")
                        continue
                    # 실행 가능한 명령은 옵션 조합(경우의 수) 변형까지 시도.
                    # variant_stats 가 있으면 학습된 성공률로 변형 순서를 재정렬한다.
                    for vcmd in expand_variants(cmd, self.max_variants, self.variant_stats):
                        if vcmd in seen:
                            continue
                        seen.add(vcmd)
                        if key not in buckets:
                            buckets[key] = []
                            order.append(key)
                        buckets[key].append((cmd, vcmd))
        # 2) 서비스 round-robin 으로 예산 분배 — 각 서비스가 먼저 한 개씩 돌 기회를 갖는다.
        #    (미설치 도구는 예산을 쓰지 않음 — 기존 의미 유지). 버킷이 하나면 기존과 동일 순서.
        to_run: list[tuple[str, str]] = []
        slots = 0
        idxs = {k: 0 for k in order}
        while slots < budget:
            advanced = False
            for key in order:
                if slots >= budget:
                    break
                i = idxs[key]
                if i >= len(buckets[key]):
                    continue
                idxs[key] = i + 1
                advanced = True
                base, vcmd = buckets[key][i]
                to_run.append((base, vcmd))
                if self._tool_ok(vcmd):
                    slots += 1
            if not advanced:
                break
        # 예산 초과로 못 돌린 후보는 수동 제안으로 남긴다
        for key in order:
            for _base, vcmd in buckets[key][idxs[key]:]:
                report.manual_suggestions.append(vcmd + "   # (상한 초과 — 수동)")
        if not to_run:
            return 0
        base_by_cmd = {vcmd: base for base, vcmd in to_run}
        if self.max_parallel <= 1:
            # 순차(기본): 게이트→실행→처리→변형학습 기록
            for base_cmd, vcmd in to_run:
                if self._goal_reached(report):   # 목표 달성 — 남은 후보는 실행하지 않음
                    break
                before = len(report.enum_findings)
                self._attempt(report, report.enum_findings, vcmd, phase)
                if len(report.enum_findings) > before:
                    self._record_variant_outcome(base_cmd, report.enum_findings[-1])
        else:
            # 병렬: 게이트(순차)→runner.run(동시)→처리(순차) 후 변형학습 기록
            gated = self._attempt_batch(report, report.enum_findings,
                                        [v for _, v in to_run], phase)
            for f in gated:
                self._record_variant_outcome(base_by_cmd.get(f.command, f.command), f)
        return len(to_run)

    def _record_variant_outcome(self, base_cmd: str, finding: EnumFinding) -> None:
        """실행된 변형의 결과(성공/실패)를 학습 통계에 기록. base 명령(fragment 없음)은
        학습 대상 아님. 성공 = 실행됐고 쓸만한 출력이 있음(요약 비어있지 않음)."""
        if self.variant_stats is None or finding is None:
            return
        frag = fragment_of(base_cmd, finding.command)
        if not frag:
            return
        success = bool(finding.ran and finding.output)
        self.variant_stats.record(binary_of(finding.command, strip_path=True), frag, success)

    def _harvest_creds(self, stdout: str, cmd: str, finding: EnumFinding) -> None:
        """출력에서 고신뢰 평문 자격을 수확한다. 월드엔 모두 반영(권한레벨 상승 →
        A1 재진입 활성화), 실행 볼트엔 셸-안전한 값만 추가(인젝션 차단). 중복은 무시.
        일반 harvest 에 더해, 노출된 설정파일 본문(FreePBX amportal 의 AMPDBUSER/AMPDBPASS 등
        제품 특수 키)도 파싱한다 — 웹 노출 설정/백업에서 발판 전에 자격을 얻기 위함."""
        from . import cred_sources
        pairs = list(harvest_creds(stdout))
        for _u, _p, _lbl in cred_sources.parse_config_creds(stdout):
            if (_u, _p) not in pairs:
                pairs.append((_u, _p))
        if not pairs:
            return
        from .creds import Credential
        for user, pw in pairs:
            if self.world is not None:
                self.world.add_cred(f"{user}:{pw}", source=binary_of(cmd, strip_path=True))
            self.audit.event("cred_harvested", cmd=cmd, user=user)
            note = f"🔑 크리덴셜 발견: {user}"
            finding.note = (finding.note + " " if finding.note else "") + note
            # 실행 볼트 추가는 셸-안전한 값만(신뢰불가 출처 → 명령 인젝션 방지)
            if (self.vault is not None and is_safe_for_cmd(user)
                    and is_safe_for_cmd(pw)):
                self.vault.add(Credential(username=user, password=pw,
                                          source="harvested"))

    def _expand(self, tmpl: str, target: str) -> list[tuple[str, bool]]:
        """볼트가 있으면 자격증명으로 플레이스홀더를 채워 확장, 없으면 {t}만 치환.
        그 전에, 관측으로 식별된 웹앱 제품/버전이 있으면 {product}/{version} 을 먼저
        채운다 → 'searchsploit {product} {version}' 이 'searchsploit freepbx 15.0' 처럼
        자동 실행 가능한 구체 명령이 된다(미식별이면 placeholder 로 남아 수동 제안)."""
        tmpl = self._fill_fingerprint(tmpl)
        if self.vault is not None:
            return self.vault.expand(tmpl, target)
        cmd, auto = self.kb.format_suggestion(tmpl, target)
        return [(cmd, auto)]

    def _fill_fingerprint(self, tmpl: str) -> str:
        """{product}/{version} 을 월드의 웹앱 핑거프린트(없으면 nmap 서비스 제품)로 치환.
        값이 없으면 placeholder 를 그대로 둬 수동 제안으로 남긴다(섣부른 치환 금지)."""
        w = self.world
        if w is None:
            return tmpl
        product = w.web_product
        version = w.web_version
        if not product:   # 웹앱 미식별 → nmap -sV 서비스 제품으로 폴백
            for s in w.services:
                if s.product:
                    product = s.product.split()[0]
                    version = version or s.version
                    break
        if product and "{product}" in tmpl:
            tmpl = tmpl.replace("{product}", product)
        if version and "{version}" in tmpl:
            tmpl = tmpl.replace("{version}", version)
        # 버전 미상이면 'searchsploit {product} {version}' → 'searchsploit freepbx' 로 정리
        # ({version} 만 남아 수동 제안으로 떨어지는 것 방지 — 제품만으로도 유효한 조회).
        if product and "{version}" in tmpl and not version:
            tmpl = re.sub(r"\s*\{version\}", "", tmpl)
        return tmpl

    def _prereq_met(self, phase: str) -> tuple[bool, str]:
        """A2: 단계 전제조건 판정. 월드 모델의 권한레벨·크리덴셜로 결정한다.
        enum/access 는 항상 가능. privesc/lateral 은 발판(쉘)·크리덴셜이 있어야
        투기적 LLM 제안이 의미있다(없으면 KB 수동 가이드만 남긴다)."""
        w = self.world
        if w is None or phase in ("enum", "access"):
            return True, ""
        has_foothold = w.has_access("user")
        has_cred = bool(w.creds)
        has_secret = bool(w.loot) or has_cred   # 해시/자격 등 측면이동 수단
        if phase == "privesc":
            if has_foothold or has_cred:
                return True, ""
            return False, "전제 미충족: user 쉘 또는 크리덴셜 필요"
        if phase == "lateral":
            if has_foothold or has_secret:
                return True, ""
            return False, "전제 미충족: 크리덴셜/해시 등 이동수단 필요"
        return True, ""

    def _note_terms(self, host: NmapHost, prof: ProfileResult,
                    phase: str, report: OrchestrationReport) -> list[str]:
        """B5: 노트 관련도 랭킹용 쿼리 용어 — 서비스·OS·단계·탐지 취약점에서 수집."""
        terms: list[str] = []
        if host is not None:
            for p in host.ports:
                if p.state == "open" and p.service:
                    terms.append(p.service)
                    prod = getattr(p, "product", "") or ""
                    if prod:
                        terms.append(prod.split()[0])
        if prof is not None:
            terms.append(prof.os_class.value)
        terms.append(_PHASE_LABEL.get(phase, phase))
        terms.append(phase)
        terms += list(report.detected_cve)
        return terms

    def _acquire_knowledge(self, report: OrchestrationReport, host: NmapHost,
                           prof: ProfileResult) -> None:
        """자율 지식 획득 — 관측된 기술 용어 중 '모르는 것'을 감지해 권위 출처에서
        자동 학습(allowlist·P1 가드 내장)하고, 현재 KB 에 즉시 반영한다. 매핑 불가
        용어는 지어내지 않고 report.knowledge_gaps 에 기록(수동 조사 안내)."""
        if not self.learn_gaps:
            return
        from . import knowledge_gaps as kg
        terms = self._note_terms(host, prof, "enum", report)
        # 분석가가 지목한 기술 키워드도 공백 후보로(있으면) — 상태 성장 반영
        remaining = self.max_gap_learn - len(self._acquired_topics)
        if remaining <= 0:
            # 예산 소진 — 미해석 공백만 계속 기록(학습 생략)
            out = kg.acquire(terms, self.kb, None, self._acquired_topics, 0)
        else:
            out = kg.acquire(terms, self.kb, self.learner,
                             self._acquired_topics, max(0, remaining),
                             web_learner=self.web_learner)
        for line in out.acquired:
            if line not in report.acquired_knowledge:
                report.acquired_knowledge.append(line)
                self.audit.event("knowledge_acquired", detail=line)
                if self.world is not None:
                    # loot 이 아니라 learned 로 — 학습 토픽은 측면이동 수단이 아니므로
                    # lateral 전제(bool(loot))를 충족시키면 안 된다(MED-1 상태오염 수정).
                    self.world.add_learned(f"자율학습: {line}")
        for term in out.unresolved:
            if term not in report.knowledge_gaps:
                report.knowledge_gaps.append(term)
                self.audit.event("knowledge_gap", term=term)

    @staticmethod
    def _low_confidence(report: OrchestrationReport) -> bool:
        """B6: 분석가 산출의 '확신도' 가 낮으면(하/low) True. 적응형 tier 상향 근거."""
        text = (getattr(report, "analysis", "") or "")
        # '확신도: 하' 처럼 항목 값의 첫 등급만 본다(근거 문장 속 '하위'·'below' 오탐 방지).
        # 다관점 분석은 가설 줄에 '[우선:하]' 도 쓰므로 '확신도' 항목 줄만 대상으로 한다.
        for ln in text.splitlines():
            m = re.match(r"\s*(?:확신도|confidence)\s*[:：]\s*\(?\s*(상|중|하|high|medium|low)",
                         ln, re.I)
            if m:
                return m.group(1).lower() in ("하", "low")
        return False

    def _run_analyst(self, report: OrchestrationReport, prof: ProfileResult,
                     host: NmapHost, target: str) -> None:
        """B3 분석가 — 상태를 읽고 가설·공격경로·다음집중·확신도를 산출해
        report.analysis 에 저장(이후 명령 생성 컨텍스트로 주입). LLM 없으면 no-op."""
        if self.llm_router is None or not hasattr(self.llm_router, "analyze"):
            return
        prior = [f"{f.command} => {f.output}"
                 for f in (report.enum_findings + report.llm_findings) if f.output]
        context = {
            "platform": self.platform_name,
            "profile": prof.summary() if prof else "",
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            "state": self.world.context_lines() if self.world is not None else [],
            "findings": prior[-10:],
            "failures": self._failure_context(report),
            # 갱신 모드: 이전 가설 기록·막힌 가설을 넘겨 '처음부터 다시'가 아니라 이어서 판단
            "ledger": report.plan.context_lines(),
            "stuck": [h.id for h in report.plan.stuck()],
            **self._exec_context(),
        }
        # 분석가 티어 적응화: 추론 난이도가 높은 국면(첫 분석=기록 없음 · 막힌 가설 존재 ·
        # 직전 확신도 낮음)에만 STRONG(opus), 평상시 갱신은 STANDARD(sonnet)로 비용 절감.
        from .llm.base import Tier
        hard = (not context["ledger"] or bool(context["stuck"])
                or self._low_confidence(report))
        tier = Tier.STRONG if hard else Tier.STANDARD
        try:
            text = self.llm_router.analyze(context, target, tier=tier)
        except Exception as e:   # 분석 실패는 전체를 깨지 않는다
            self.audit.event("analyst_error", error=str(e))
            return
        if text:
            before = report.plan.focus()
            n = report.plan.apply_text(text)
            report.analysis = strip_ledger_json(text)
            self.audit.event("analyst", chars=len(text), text=report.analysis[:2000])   # 재생 뷰어용
            if n:
                self.audit.event("plan_update", revision=report.plan.revision,
                                 board=report.plan.board_lines())
            after = report.plan.focus()
            if after is not None and (before is None or before.id != after.id) and not self.quiet:
                from . import ui
                print("  " + ui.accent2("🎯 지금 집중: ") + f"{after.id} {after.text}")

    def _llm_round(self, report: OrchestrationReport, host: NmapHost,
                   prof: ProfileResult, target: str,
                   seen: set[str], budget: int, phase: str = "enum") -> int:
        """해당 단계의 LLM 제안 한 라운드. 이전 관측을 컨텍스트에 반영(적응)."""
        router = self.llm_router
        if budget <= 0 or router is None:   # 호출부가 이미 router 를 확인 — 타입 명시용
            return 0
        # 라운드 사이에 가설이 확인·기각·막힘이 되었으면 여기서 재계획(지문 기준, 변화 없으면 생략)
        self._refresh_analysis(report, prof, host, target)
        focus = report.plan.focus()
        # ④ 논리적 흐름: 가설 원장이 있는데 쫓을 대상이 하나도 없고(focus 없음) 모든 열린
        # 가설이 '막힘'이면, 같은 상태에서 투기적 LLM 제안을 또 돌리지 않는다(토큰 낭비 방지).
        # KB 열거는 계속 돌고, 다음 스윕에서 상태가 자라면 분석가가 가설을 다시 연다.
        if report.plan.items and focus is None and report.plan.stuck():
            self.audit.event("llm_round_skipped", phase=phase,
                             reason="all-hypotheses-stuck")
            return 0
        context = self._suggest_context(report, host, prof, phase, focus)
        try:
            from .llm.base import Tier, tier_for_phase
            base_tier = tier_for_phase(phase)
            # B6 적응형 tier: 분석 확신도 '하' 면 처음부터 강력 모델로 상향
            if self._low_confidence(report) and base_tier != Tier.STRONG:
                base_tier = Tier.STRONG
                self.audit.event("tier_escalate", reason="low_confidence", phase=phase)
            cmds = router.suggest_commands(
                context, target, tier=base_tier, max_items=budget)
            # B6: 저단계 모델이 쓸만한 명령을 못 내면(빈 결과) 강력 모델로 1회 승격 재시도
            if not cmds and base_tier != Tier.STRONG:
                self.audit.event("tier_escalate", reason="empty_result", phase=phase)
                cmds = router.suggest_commands(
                    context, target, tier=Tier.STRONG, max_items=budget)
        except Exception as e:  # LLM 백엔드 오류는 전체를 깨지 않는다
            report.manual_suggestions.append(f"(LLM 제안 실패: {e})")
            return 0
        meta = getattr(self.llm_router, "last_meta", {}) or {}
        attempted = 0
        # 예산·중복·목표 선검사로 이번 라운드에 돌릴 후보를 모은다. 파일 액션(익스플로잇·솔버
        # 스크립트)은 다단계일 수 있어 '순차'로, 파일 없는 일반 프로브는 enum 과 동일하게 '병렬'로.
        files: list[tuple[str, dict]] = []
        plain: list[tuple[str, dict]] = []
        for cmd in cmds:
            m = meta.get(cmd) or {}
            # 같은 실행 명령이라도 스크립트 본문이 바뀌었으면 새 시도(익스플로잇 반복 개선)
            key = cmd
            if m.get("file"):
                import hashlib
                key += "  #file:" + hashlib.sha256(
                    str(m["file"].get("content", "")).encode("utf-8")).hexdigest()[:16]
            if key in seen:
                continue
            if attempted >= budget or self._goal_reached(report):
                break
            seen.add(key)
            (files if m.get("file") else plain).append((cmd, m))
            if self._tool_ok(cmd):
                attempted += 1
        # 일반 명령: 병렬 배치(게이트 순차→I/O 동시→처리 순차). 게이트는 cmd 당 finding 을 하나씩
        # 순서대로 쌓으므로, 제출 순서로 zip 해 가설·근거·신호 비고를 올바른 finding 에 붙인다.
        if plain:
            n0 = len(report.llm_findings)
            if self.max_parallel > 1 and len(plain) > 1:
                self._attempt_batch(report, report.llm_findings, [c for c, _ in plain], phase)
            else:
                for c, _m in plain:
                    if self._goal_reached(report):
                        break
                    self._attempt(report, report.llm_findings, c, phase)
            for (_c, m), f in zip(plain, report.llm_findings[n0:]):
                self._tag_llm_finding(report, f, m, focus)
        # 파일 액션: 순차 — 작성→실행→태깅(파일을 못 쓰면 그 파일을 쓰는 명령도 돌리지 않음)
        for cmd, m in files:
            if self._goal_reached(report):
                break
            written = self._write_file_action(report, cmd, m["file"])
            if written is None:
                continue
            n_before = len(report.llm_findings)
            self._attempt(report, report.llm_findings, cmd, phase)
            ff: "EnumFinding | None" = (report.llm_findings[-1]
                                        if len(report.llm_findings) > n_before else None)
            self._tag_llm_finding(report, ff, m, focus, written)
        return attempted

    def _tag_llm_finding(self, report: OrchestrationReport, f: "EnumFinding | None",
                         m: dict, focus, written: str = "") -> None:
        """실행된 LLM 명령 finding 에 파일작성·가설·근거·기대신호 대조 비고를 덧붙인다
        (순차·병렬 공용). f 가 None(실행 전 목표 달성 등)이면 no-op."""
        if f is None:
            return
        if written:
            f.note = (f.note + " · " if f.note else "") + f"📝 파일 작성: {written}"
        # B4: 구조화 출력의 가설·근거(어느 가설을 검증했는지 추적)
        tags = [t for t in (("가설 " + m["hypothesis"]) if m.get("hypothesis") else "",
                            ("근거: " + m["rationale"]) if m.get("rationale") else "") if t]
        sig = self._record_signal(report, f, m, focus)
        if sig:
            tags.append(sig)
        if tags:
            f.note = (f.note + " · " if f.note else "") + " · ".join(tags)

    def _suggest_context(self, report: OrchestrationReport, host: NmapHost,
                         prof: ProfileResult, phase: str, focus) -> dict:
        """명령 생성(suggest)용 LLM 컨텍스트 조립 — 관측·월드·분석가 판단·focus·KB·플랫폼을
        정돈해 한 dict 로. (_llm_round 에서 분리: 로직 밀도 완화)"""
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
        prior = [f"{f.command} => {f.output}"
                 for f in (report.enum_findings + report.llm_findings) if f.output]
        return {
            "phase": _PHASE_LABEL.get(phase, phase),
            "profile": prof.summary(),
            # 구조화 상태(월드 모델) — 원시 로그 대신 정돈된 사실을 LLM 에 제공
            "state": self.world.context_lines() if self.world is not None else [],
            # B3 분석가의 판단 — 명령 생성을 유도(가설·경로·집중)
            "analysis": report.analysis,
            # 실행자에게는 분석 전문 대신 '지금 할 일 1개'(가설·확인 방법·기대 신호·이미 한 시도)
            "focus": report.plan.focus_lines(focus) if focus is not None else [],
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            # 명령 없는 가이드 규칙은 이름만 가면 쓸모가 없으므로 가이드(note) 앞부분을 전달
            "kb": [f"{r.rule_name}: " + (", ".join(r.suggestions)
                                          or (r.note[:160] + ("…" if len(r.note) > 160 else "")))
                   for r in recs[:5]],
            # B5(경량 RAG): 현재 서비스·OS·단계·취약점에 관련도 높은 노트만 주입
            "notes": self.kb.relevant_notes(
                self._note_terms(host, prof, phase, report), 3),
            "findings": prior[-10:],
            "failures": self._failure_context(report),
            # 플랫폼 인식 — LLM 프롬프트가 HTB/Jeopardy·카테고리에 맞게 조립된다
            "platform": self.platform_name,
            "jeopardy": self.flag_kind == "single",
            "category": self.category,
            "flag_prefixes": ("/".join(f"{p}{{...}}" for p in self.flag_prefixes)
                              if self.flag_prefixes else ""),
            **self._exec_context(),
        }

    def _exec_context(self) -> dict:
        """LLM 프롬프트용 실행 환경(셸 문법·작업공간 쓰기 가능 여부) + 작업공간 파일 발췌."""
        shell = bool(getattr(self.runner, "shell", False))
        contained = bool(getattr(self.runner, "contained", False))
        ctx: dict = {"exec": {"shell": shell, "contained": contained,
                              "workspace": self.workspace is not None and contained}}
        if self.workspace is not None:
            try:
                ctx["workspace"] = self.workspace.context_lines()
            except OSError as e:
                self.audit.event("workspace_error", error=str(e))
        return ctx

    def _write_file_action(self, report: OrchestrationReport, cmd: str,
                           fobj: dict) -> str | None:
        """LLM 파일 액션(스크립트 작성). 성공 시 상대경로, 거부 시 None(명령도 실행 안 함).
        정적 범위 검사는 스크립트 본문 속 접속 대상을 볼 수 없으므로, 네트워크가 실행 계층에서
        강제되는(contained) 실행기에서만 자동으로 쓰고 실행한다."""
        path = str(fobj.get("path", ""))[:200]
        if self.dry_run:   # 계획 미리보기 — 파일을 쓰지 않고 경로만 반환(이후 명령도 실행 안 됨)
            return path or None
        content = str(fobj.get("content", ""))
        if self.workspace is None or not getattr(self.runner, "contained", False):
            reason = ("작업공간 없음" if self.workspace is None
                      else "egress 강제 실행기 아님 — --sandbox docker 필요")
            entry = f"{cmd}   # (스크립트 {path} 필요 · {reason} — 수동)"
            if entry not in report.manual_suggestions:
                report.manual_suggestions.append(entry)
            self.audit.event("file_denied", path=path, cmd=cmd, reason=reason)
            return None
        from .workspace import WorkspaceError
        try:
            rel = self.workspace.write_file(path, content)
        except (WorkspaceError, OSError) as e:
            report.manual_suggestions.append(f"{cmd}   # (스크립트 저장 거부: {e})")
            self.audit.event("file_denied", path=path, cmd=cmd, reason=str(e))
            return None
        # 원격 실행기(VM 등)는 작업공간이 로컬에만 있으므로 파일을 실행 호스트로 올린다.
        # (Docker 는 작업공간을 바인드 마운트하므로 동기화 불필요 — sync_file 없음)
        syncer = getattr(self.runner, "sync_file", None)
        if callable(syncer):
            try:
                syncer(self.workspace.resolve(rel), rel)
            except Exception as e:   # noqa: BLE001 — 동기화 실패 시 그 명령은 실행하지 않음
                report.manual_suggestions.append(f"{cmd}   # (스크립트 전송 실패: {e})")
                self.audit.event("file_sync_error", path=rel, cmd=cmd, error=str(e))
                return None
        import hashlib
        self.audit.event("file_written", path=rel, cmd=cmd, size=len(content),
                         sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                         content=content[:4000])
        return rel

    def _record_signal(self, report: OrchestrationReport, f: EnumFinding, meta: dict,
                       focus) -> str:
        """LLM 명령 결과를 가설의 기대 신호와 대조(규칙 기반)해 가설 기록을 갱신한다.
        반환: 비고에 붙일 짧은 표시(없으면 ""). 가설 ID 는 명령 메타 → 이번 라운드 초점 순."""
        hid = parse_id(meta.get("hypothesis", "")) or (focus.id if focus is not None else "")
        h = report.plan.get(hid) if hid else None
        if h is None:
            return ""
        last = report.blockers[-1] if report.blockers else None
        rejected = bool(last and last[0] == f.command and last[1].is_target)
        human = f.output.startswith("[사람 관찰]")
        expected = meta.get("expected") or ""
        if expected and not h.expected:
            h.expected = expected[:120]   # 가설에 기대 신호가 없으면 명령의 기대 신호를 채택
        res = report.plan.record(hid, f.command, f.output, f.ran and not human, rejected)
        if res == "neutral":
            return ""
        self.audit.event("hypothesis_signal", hypothesis=hid, cmd=f.command, result=res,
                         status=h.status, misses=h.misses)
        if res == "miss" and h.misses == report.plan.replan_after:
            self.audit.event("hypothesis_stuck", hypothesis=hid, misses=h.misses)
            if not self.quiet:
                from . import ui
                print("  " + ui.mark_warn(f"{hid} 기대 신호 {h.misses}회 연속 불일치 — 분석가에게 재계획 요청"))
        return f"{hid} 신호 일치〔추정〕" if res == "hit" else f"{hid} 신호 불일치"

    def _run_vuln(self, report: OrchestrationReport, host: NmapHost, target: str) -> None:
        """관측 코퍼스(배너·스크립트·enum/LLM 출력)에서 CVE/CWE·버전 매칭을 탐지해 리포트·월드에
        반영한다. 스윕 중 반복 호출되며(분석·명령 생성이 '확인 취약점'을 보도록) 결과는 누적·멱등."""
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
        corpus_text = "\n".join(corpus_parts)
        hits = extract_vuln_ids(corpus_text)
        report.detected_cve = hits.cves
        report.detected_cwe = hits.cwes
        if self.vuln_kb is not None:
            report.vuln_matches = self.vuln_kb.match(banners, target)
        # 웹앱 핑거프린트: 관측 코퍼스(제목·generator·배너·enum 출력)에서 알려진 제품/버전을
        # 식별해 월드에 기록 → searchsploit {product} {version} 등 KB placeholder 가 '실제 값'
        # 으로 치환돼 자동 실행 후보가 된다(식별 전엔 placeholder 로 남아 수동 제안).
        if self.world is not None:
            from .vuln import fingerprint_webapp
            # 핑거프린트는 '요약(finding.output)'이 아니라 '원본(raw_output)'에서 한다 — 요약기
            # (parse_http 등)의 엄격 정규식에 버전이 걸러져 web_version 이 비는 구조적 버그 교정.
            # searchsploit 출력은 제외(여러 버전 익스 제목이 타겟 버전으로 오탐되는 것 방지).
            fp_parts = list(host.hostscripts.values())
            for p in host.ports:
                if p.state == "open":
                    if p.banner:
                        fp_parts.append(p.banner)
                    fp_parts.extend(p.scripts.values())
            for f in report.enum_findings + report.llm_findings:
                if f.command.strip().startswith("searchsploit"):
                    continue
                txt = f.raw_output or f.output
                if txt:
                    fp_parts.append(txt)
            prod, ver = fingerprint_webapp("\n".join(fp_parts))
            if prod:
                self.world.set_web_app(prod, ver)
        # 월드 모델에 확인 취약점 반영(단일 상태원)
        if self.world is not None:
            for cve in report.detected_cve + report.detected_cwe:
                self.world.add_vuln(cve, source="관측 출력(배너·스크립트·명령 결과)")
            for m in report.vuln_matches:
                ids = " ".join(m.cve + m.cwe)
                self.world.add_vuln(f"{m.name}" + (f" ({ids})" if ids else ""),
                                    source="버전 매칭(VulnKB)")
    def _web_bases(self, host: NmapHost) -> list[str]:
        """관측된 열린 웹 포트에서 'scheme://ip[:port]' 베이스 URL 목록을 만든다.
        표준 포트(80/http, 443/https)는 포트를 생략. TLS 판정은 서비스명(https/ssl)·
        포트(443/8443)로. https 베이스를 http 보다 앞에 둔다(FreePBX 등은 주로 TLS)."""
        ip = (self.world.target if self.world else "") or host.address
        if not ip:
            return []
        https: list[str] = []
        http: list[str] = []
        for p in host.ports:
            if p.state != "open":
                continue
            svc = (p.service or "").lower()
            banner = (p.banner or "").lower()
            is_web = ("http" in svc or p.port in (80, 443, 8080, 8443, 8000, 8888)
                      or "http" in banner)
            if not is_web:
                continue
            tls = (svc in ("https", "ssl/http") or "ssl" in svc or "https" in banner
                   or p.port in (443, 8443))
            if tls:
                base = f"https://{ip}" if p.port == 443 else f"https://{ip}:{p.port}"
                if base not in https:
                    https.append(base)
            else:
                base = f"http://{ip}" if p.port == 80 else f"http://{ip}:{p.port}"
                if base not in http:
                    http.append(base)
        return https + http

    def _version_probe_stage(self, report: OrchestrationReport, host: NmapHost,
                             phase: str = "enum") -> None:
        """웹앱 제품은 식별됐으나 버전이 미상일 때, 문서화된 '버전 노출' 경로를 무해한 GET 으로
        긁어 버전을 집어낸다(제품당 1회·멱등). 익스/RCE 아님 — 조회 GET 뿐(생성 전용 경계).
        프로브 출력은 enum_findings 에 남고, 이어 _run_vuln 재실행이 fingerprint_webapp 으로
        버전을 추출해 월드에 반영한다 → 다음 _exploit_lookup_stage 에서 ⭐ 자동 선택 가능.
        버전이 끝내 안 보이면 '미상' 을 유지한다(섣부른 단정 금지 — 정직성)."""
        if self.world is None:
            return
        prod = self.world.web_product
        # 제품 미식별 / 이미 버전 확보 / 이미 프로브함 → 아무것도 안 함(멱등·노이즈 억제)
        if not prod or self.world.web_version or prod in self._version_probed:
            return
        from .exploits import probes_for
        bases = self._web_bases(host)
        if not bases:
            return
        self._version_probed.add(prod)
        # 베이스당 프로브 — 과도한 요청 방지를 위해 상위 2개 베이스로 제한.
        for base in bases[:2]:
            for cmd in probes_for(prod, base):
                if self._goal_reached(report) or self._time_up():
                    break
                self._attempt(report, report.enum_findings, cmd, phase=phase)
        # 프로브 출력에서 버전 즉시 추출(다음 _run_vuln 을 기다리지 않고 이번 스윕에 반영).
        self._run_vuln(report, host, self.world.target)

    def _web_fingerprint_stage(self, report: OrchestrationReport,
                               host: NmapHost | None = None, phase: str = "access") -> None:
        """vhost 로 리다이렉트를 따라가(-L) 웹앱 제품/버전을 '결정적으로' 핑거프린트한다.
        LLM 명령 편차로 admin 페이지(200 본문의 'appver=FreePBX …')에 도달 못 해 제품이
        미식별되던 문제 교정 — 302 리다이렉트에서 멈추면 FreePBX 가 코퍼스에 안 들어온다.
        무해 GET(-L). opt-in(--exploit-exec/--auto-poc)·vhost 당 1회. 제품 미상일 때만."""
        if self.world is None or self.world.web_product:
            return                      # 이미 식별됐으면 불필요
        if host is None or not (self.exploit_exec or self.auto_poc):
            return
        bases = self._web_bases(host)
        tgt = self.world.target
        vhosts = [h for h, ip in (self.hosts_map or {}).items() if ip == tgt]
        if not bases or not vhosts:
            return                      # vhost 미등록이면(아직 리다이렉트 관측 전) 다음 스윕에
        from .web_secrets import _HOST_SAFE
        key = ",".join(sorted(bases)) + "|" + ",".join(sorted(vhosts))
        if key in self._web_fp_probed:
            return
        self._web_fp_probed.add(key)
        # https 베이스 1개 × vhost × 대표 경로(루트·admin·config.php) — -L 로 200 본문까지.
        for vh in vhosts:
            if not _HOST_SAFE.match(vh):
                continue
            for p in ("", "admin/", "admin/config.php"):
                if self._goal_reached(report) or self._time_up():
                    break
                cmd = f'curl -s -L -k --max-time 10 -H "Host: {vh}" {bases[0]}/{p}'
                self._attempt(report, report.enum_findings, cmd, phase=phase)
        # 새 관측을 즉시 반영 → 이번 스윕의 뒤 단계(web_secret·lookup)가 제품을 바로 활용.
        self._run_vuln(report, host, tgt)

    def _web_secret_stage(self, report: OrchestrationReport,
                          host: NmapHost | None = None, phase: str = "access") -> None:
        """웹 노출 비밀/백업 파일을 '읽기 전용 GET'으로 열거 → 발판 전에 HTTP 로 자격 수확.
        무해한 curl -s 만 생성해 3관문에 올린다(gobuster/curl 열거와 동일 위험군, 실행 아님).
        본문→자격 추출은 기존 _harvest_creds 가 원시출력에서 수행 → world.creds 에 반영되면
        ①(b) 가 인증 필요 PoC 를 자동 발사 큐에 올릴 수 있다(자격 선확보 폐루프). 호스트당 1회.

        공격 지향 열거라 자동 루트 시도(--exploit-exec/--auto-poc) 때만 돈다 — 기본·순수 정찰
        모드의 명령 폭·예산을 늘리지 않기 위함(옵트인)."""
        if host is None or self.world is None:
            return
        if not (self.exploit_exec or self.auto_poc):
            return
        bases = self._web_bases(host)
        if not bases:
            return
        # vhost 기반 앱(connected.htb 등)은 IP 기본 vhost 로는 못 본다 → 등록된 vhost 로 때린다.
        tgt = self.world.target
        vhosts = [h for h, ip in (self.hosts_map or {}).items() if ip == tgt]
        key = (",".join(sorted(bases)) + "|" + ",".join(sorted(vhosts))
               + "|" + (self.world.web_product or ""))
        if key in self._web_secret_probed:
            return
        self._web_secret_probed.add(key)
        from .web_secrets import secret_read_commands
        for cmd in secret_read_commands(bases, self.world.web_product or "", vhosts=vhosts):
            if self._goal_reached(report) or self._time_up():
                break
            self._attempt(report, report.enum_findings, cmd, phase=phase)

    def _exploit_lookup_stage(self, report: OrchestrationReport,
                              host: NmapHost | None = None, phase: str = "access") -> None:
        """핑거프린트된 웹앱 제품(world.web_product)에 맞는 공개 익스 '조회' 명령
        (searchsploit)을 게이트로 올린다. 조회·로컬·무해 — 익스 실행이 아니다(생성 경계).
        제품당 1회만(멱등). 조회 결과(버전별 공개 익스 목록)는 enum_findings 에 남아 다음
        분석·명령 생성에 되먹여진다. 특정된 PoC 는 대상 버전 대조 후 사람/LLM 이 골라 실행."""
        if self.world is None:
            return
        prod = self.world.web_product
        if not prod or prod in self._exploit_looked_up:
            return
        from .exploits import lookups_for, note_for
        cmds = lookups_for(prod)
        if not cmds:
            return
        self._exploit_looked_up.add(prod)
        for cmd in cmds:
            if self._goal_reached(report) or self._time_up():
                break
            self._attempt(report, report.enum_findings, cmd, phase=phase)
        note = note_for(prod)
        report.manual_suggestions.append(
            f"# {prod} 공개 익스 후보 — searchsploit 결과에서 '대상 버전'에 맞는 PoC 를 "
            f"골라 3관문(검증·범위·승인)으로 실행하세요(권한 확인 대상 전용)"
            + (f"\n#   ↳ {note}" if note else ""))
        # ⭐ 버전매칭 PoC 숏리스트/제안은 '전체 searchsploit 증거 + 최종 버전'으로 재평가한다
        # (제품은 잡혔으나 버전이 enum 단계에서 늦게 확정되는 경우가 많아, 조기 1회 평가가
        # '매칭 없음'으로 굳는 것을 막기 위함). 생성 전용 — 파싱·제안·--poc 큐잉만.
        self._refresh_exploit_shortlist(report, host)

    def _refresh_exploit_shortlist(self, report: OrchestrationReport,
                                   host: NmapHost | None = None) -> None:
        """searchsploit 결과 '전체'를 모아 대상 버전 매칭 PoC 숏리스트/⭐ 제안을 (재)계산한다.
        _exploit_lookup_stage 가 제품당 1회만 도는 것과 달리, 이 패스는 버전·searchsploit
        증거가 나중에 더 채워져도(버전은 enum 단계에서 늦게 잡히는 경우가 많다) 반영되도록
        호출 시마다 '전체 증거'로 다시 평가한다. 생성 전용 — 파싱·제안·--poc 큐잉만(실행 아님).

        정직성: ⭐ 1순위는 '대상 버전 실제 접두 매칭'이 있을 때만. 매칭 PoC 가 '인증 필요'
        (제목에 Authenticated 등)인데 보유 자격이 없으면, 자동 발사하지 않고 '자격 선확보'로
        안내한다(무인증 자동 익스로 뚫리지 않는 대상을 '매칭 없음'으로 오표기하지 않는다)."""
        if self.world is None or not self.world.web_product:
            return
        from .searchsploit import has_version_match, parse_searchsploit, shortlist
        # 특정 조회 창(before:)이 아니라, 리포트 전체의 searchsploit 산출을 모은다 — 조회
        # 단계 외(LLM·수동 참고 등)에서 돈 searchsploit 결과도 포함해 증거 결손을 없앤다.
        hits: list = []
        seen_titles: set[str] = set()
        # enum + llm 양쪽 모두 스캔 — searchsploit 가 LLM 제안으로 돌면 llm_findings 에
        # 저장돼 enum 만 보면 증거를 놓친다(⭐ 매칭 누락의 한 원인).
        for f in list(report.enum_findings) + list(report.llm_findings):
            if "searchsploit" not in (f.command or ""):
                continue
            # 요약은 상위 12행만 보존 → 매칭 PoC 가 13위 밖이면 소실. 원본(raw)에서 전체 파싱.
            for h in parse_searchsploit(f.raw_output or f.output or ""):
                if h.title not in seen_titles:
                    seen_titles.add(h.title)
                    hits.append(h)
        if not hits:
            return
        prod = self.world.web_product
        version = (self.world.web_version or "").strip()   # 공백 혼입 방어(접두 매칭 오류 방지)
        picks = shortlist(hits, version, limit=6)
        if not picks:
            return
        matched = has_version_match(hits, version)
        # 진단(감사 로그) — ⭐ 매칭이 왜 성립/불성립했는지 사후 확인용(version·hit 버전·결과).
        self.audit.event("shortlist_eval", version=version, n_hits=len(hits),
                         matched=matched,
                         hit_versions=[h.versions for h in hits[:14]])
        # 이 패스가 이전에 남긴 숏리스트 제안을 먼저 제거(마커로 식별) — 중복 누적 방지, 최신본만.
        marker = "PoC 후보(버전"
        report.manual_suggestions[:] = [
            s for s in report.manual_suggestions if marker not in s]
        rows = []
        for i, h in enumerate(picks):
            star = (i == 0 and matched)
            rows.append(f"#   {'⭐ 추천' if star else '      '} - {h}")
        fetch = ""
        if matched:
            # ⭐ 1순위 PoC 의 '받기 + 실행 계획(제안)' 구체화(생성 전용 — 문자열 생성, 실행 아님).
            from .exploit_fetch import PocPlan, fetch_command, plan_poc_command, poc_language
            top = picks[0]
            # 인증 필요 PoC 판별 — 제목의 'auth' 신호. searchsploit 요약이 제목을 잘라
            # '(Authenticated)' 가 '(Au' 로 끊기는 경우(실전 connected.htb)까지 잡는다.
            auth_required = bool(re.search(r"auth|\(au", top.title, re.I))
            have_creds = bool(self.world.creds)
            edb_id = re.search(r"(\d{4,6})", top.locator)
            eid = edb_id.group(1) if edb_id else ""
            fetch = f"\n#   ↳ 1순위 받아 검토: {fetch_command(eid)}" if eid else ""
            bases = self._web_bases(host) if host is not None else []
            scheme = "https" if any(b.startswith("https") for b in bases) else "http"
            draft = plan_poc_command(
                PocPlan(edb_id=eid, language=poc_language(top.locator), transport=scheme,
                        needs_target=True),
                self.world.target)
            if draft:
                fetch += (f"\n#   ↳ 실행 계획(제안 — 받은 소스 검토 후 조정): "
                          f"--exploit-exec --poc \"{draft}\"")
                # ⚠️ RCE 표면 — --auto-poc 옵트인 + 치명작업 y/n 확인 하에서만 자동 발사.
                # '인증 필요' PoC 를 자격 없이 발사하면 반드시 실패 → 큐잉하지 않는다(헛발사 방지).
                can_fire = (self.exploit_exec and self.auto_poc
                            and (have_creds or not auth_required))
                if can_fire and draft not in self.poc_commands:
                    self.poc_commands.append(draft)
            if auth_required and not have_creds:
                fetch += ("\n#   ↳ ⚠ 이 1순위 PoC 는 '인증 필요(Authenticated)' — 관리자 자격이 "
                          "있어야 동작한다. 먼저 자격 확보(기본·약한 자격 점검, 로그인 폼 대입, "
                          "노출된 설정/백업)한 뒤 --cred 로 넣고 재실행하면 이 PoC 가 발사된다. "
                          "자격 없이 자동 발사하지 않음(헛발사 방지).")
                head = (f"# {prod} PoC 후보(버전 {version} 대조) — ⭐=버전매칭 1순위(단, 인증 필요 → "
                        f"자격 선확보 후 발사). 권한 확인 대상 전용:")
            else:
                head = (f"# {prod} PoC 후보(버전 {version} 대조) — ⭐=자동 선택된 1순위. 받아 검토 후 "
                        f"--exploit-exec --poc \"<실행 명령>\" 로 실행(권한 확인 대상 전용):")
        elif version:
            # 버전은 '확인'됐으나 searchsploit 결과 중 이 버전과 접두 매칭되는 PoC 가 없음.
            # '버전 미상'이 아니다 — 정직하게 구분해 안내한다.
            fetch = (f"\n#   ↳ 확인된 버전 {version} 과 접두 매칭되는 PoC 가 목록에 없음. "
                     f"major 계열(예: 상위 버전대) PoC 를 사람이 직접 대조하거나, "
                     f"'searchsploit {prod} {version.split('.')[0]}' 로 재검색 권장.")
            # 진단(디버그) — '매칭 없음'이 의외일 때 실제 version·파싱된 hit 버전을 보여준다.
            fetch += (f"\n#   ↳ [진단] version={version!r} · hits={len(hits)} · "
                      f"hit_versions={[h.versions for h in hits[:14]]}")
            head = (f"# {prod} PoC 후보(버전 {version} 확인됨 · 단 매칭 PoC 없음) — 아래에서 버전대에 "
                    f"맞는 것을 골라 searchsploit -m <id> 로 받아 --exploit-exec --poc 로 실행(권한 확인 대상 전용):")
        else:
            fetch = ("\n#   ↳ 버전 확인 먼저: curl -sk https://<타겟>/admin/config.php | "
                     "grep -oiE 'freepbx[^0-9]*[0-9][0-9.]*'  (확인 후 맞는 PoC 를 searchsploit -m <id> 로)")
            head = (f"# {prod} PoC 후보(버전 미상 — 확인 후 대조 필요) — 아래에서 대상 버전에 맞는 것을 "
                    f"골라 searchsploit -m <id> 로 받아 --exploit-exec --poc 로 실행(권한 확인 대상 전용):")
        report.manual_suggestions.append(head + "\n" + "\n".join(rows) + fetch)

    def _exploit_run_stage(self, report, host):
        """3단계: 주입된 공개 PoC(--poc)를 게이트로 실행 → 자격 캡처 → world 반영."""
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        for poc in getattr(self, "poc_commands", []) or []:
            if self._goal_reached(report) or self._time_up():
                return
            before = len(report.enum_findings)
            self._attempt(report, report.enum_findings, poc, phase="access")
            from .exploit_run import harvest_creds
            for f in report.enum_findings[before:]:
                for u, p in harvest_creds(f.output or ""):
                    self.world.add_cred(f"{u}:{p}", source="PoC 출력")

    def _exploit_exec_stage(self, report, host):
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        from .target_shell import FLAG_READS, PRIVESC_ENUM, SSHTargetShell, parse_cred
        creds = []
        for c in self.world.creds:
            pc = parse_cred(c)
            if pc and pc not in creds:
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
            from .privesc_analyze import analyze_enum
            corpus = "\n".join(f.output for f in report.enum_findings if f.output)
            vectors = [v for v in analyze_enum(corpus) if v.confidence == "high" and v.plan]
            user, pw = creds[0]
            sh = SSHTargetShell(target, user, pw)
            for v in vectors[:3]:
                # v.plan 을 실행한 뒤 'id' 로 결과 확인 (한 줄로 묶어 실행)
                self._attempt(report, report.enum_findings,
                              sh.command(f"{v.plan.splitlines()[0]}; id"), phase="privesc")
                last = report.enum_findings[-1].output or ""
                if "uid=0(root)" in last:
                    self.world.raise_access("root")
                    self._attempt(report, report.enum_findings,
                                  sh.command("cat /root/root.txt 2>/dev/null"), phase="privesc")
                    break

    def _foothold_stage(self, report, host) -> None:
        """발판 세션 확보 → 자격수확 → 플래그 수집. --exploit-exec 전용(RCE 실행 표면)."""
        if not self.exploit_exec or self.world is None or self.dry_run:
            return
        session = self._acquire_session(report, host)   # ← 발판 획득(아래 TODO)
        if session is None or not session.alive:
            return
        from . import cred_sources, flag_read
        # 자격 수확
        for cmd in cred_sources.config_reads(self.world.web_product):
            out = session.run(cmd)
            for u, p, _label in cred_sources.parse_config_creds(out):
                self.world.add_cred(f"{u}:{p}", source="설정파일")
        # 플래그 수집(채널 무관)
        for kind, val in flag_read.read_flags(session, flag_kind=self.flag_kind).items():
            self.world.add_flag(kind, val)

    def _acquire_session(self, report, host):
        """발판 세션 획득 + 성립 검증. --exploit-exec/--auto-poc 전용(RCE 실행 표면).
        현재는 웹 RCE 분기만 활성 — 역쉘 수신 경로는 순서 4(실제 경로 확인) 후 재추가.
        웹 RCE 채널 전송부(shell_transport)는 requests 에 의존(선택 설치) — 미설치면 전체
        실행을 크래시내지 않고 '발판 미확보'로 안전하게 건너뛴다(정직한 degrade)."""
        if self.world is None or not (self.world.web_product and self.auto_poc):
            return None
        from .session_verify import looks_like_shell, verify_probe_command
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
        # (1) 웹 RCE 분기: cmd 엔드포인트에 명령 실행 → id/uname 신호로 성립 검증
        # PoC 가 성립시킨 cmd 엔드포인트(없으면 기본 config.php) — ②에서 정교화
        url = getattr(self, "rce_url", None) or f"https://{self.world.target}/admin/config.php"
        ws = WebRceSession(url, "cmd", method="POST", inject="body")
        ws.attach(web_http_fn)                       # ← 실제 HTTP (표면)
        # ★ 성립 검증: id/uname 신호가 없으면 헛발판 → 폐기(거짓 '발판 확보' 방지)
        if looks_like_shell(ws.run(verify_probe_command())):
            return ws
        return None

    def _prepare_revshells(self, report: OrchestrationReport) -> None:
        """공격자 IP(VPN tun0 등)가 확보되면 리버스쉘 페이로드를 자동 생성해
        리포트에 담는다. 생성 전용 — 실행은 하지 않는다(안전 경계 유지).
        공격자 IP 가 없으면(미탐지) 조용히 생략한다."""
        attacker_ips = list(self.guard.attacker_ips or [])
        if not attacker_ips:
            return
        lhost = str(attacker_ips[0])
        lport = self.revshell_port
        try:
            from . import revshell
            report.revshells = revshell.generate(lhost, lport)
            report.revshell_lhost = lhost
            report.revshell_lport = lport
            self.audit.event("revshell_prepared", lhost=lhost, lport=lport,
                             count=len(report.revshells))
        except Exception as e:   # noqa: BLE001 — 생성 실패가 전체를 깨지 않도록
            self.audit.event("revshell_error", error=str(e))

    def _prepare_cloud(self, report: OrchestrationReport) -> None:
        """호스트명/도메인이 확보되면 AWS/S3 열거(버킷 후보+점검)를 자동 준비한다.
        생성 전용 — AWS 엔드포인트는 타겟 범위 밖이라 실행하지 않는다. 버킷명 후보를
        만들 이름(호스트명/도메인)이 없으면(IP 뿐) 조용히 생략한다."""
        names: list[str] = []
        if self.hosts_map:
            names.extend(self.hosts_map.values())
            names.extend(self.hosts_map.keys())
        if self.guard.bound_host:
            names.append(str(self.guard.bound_host))
        names.append(report.target)
        try:
            from . import cloud
            prep = cloud.generate(names)
            if not prep.candidates:
                return
            report.cloud_candidates = prep.candidates
            report.cloud_checks = prep.checks
            self.audit.event("cloud_prepared", keyword=prep.keyword,
                             candidates=len(prep.candidates),
                             checks=len(prep.checks))
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("cloud_error", error=str(e))

    def _prepare_privesc(self, report: OrchestrationReport, prof: ProfileResult) -> None:
        """OS 식별 결과로 권한상승 플레이북을 자동 준비한다. 생성 전용 — 획득한
        대상 셸에서 사용자가 직접 실행한다(에이전트는 셸 없음). OS 미상이면 생략."""
        os_class = prof.os_class.value if prof else "unknown"
        if os_class not in ("linux", "windows", "windows_ad"):
            return
        attacker_ip = ""
        if self.guard.attacker_ips:
            attacker_ip = str(list(self.guard.attacker_ips)[0])
        # 탐지 CVE(출력 추출) + 버전매칭 CVE 를 합쳐 LPE 후보 승격에 반영
        cve_pool = list(report.detected_cve)
        for m in report.vuln_matches:
            cve_pool.extend(m.cve)
        try:
            from . import privesc
            plan = privesc.build(os_class, attacker_ip, cve_pool)
            report.privesc_steps = plan.steps
            report.privesc_cve_candidates = plan.cve_candidates
            self.audit.event("privesc_prepared", os=os_class,
                             steps=len(plan.steps),
                             cve_candidates=len(plan.cve_candidates))
            # ③ 폐루프 '후보 선정': 획득한 셸에서 이미 실행된 privesc 열거 출력(findings)이
            # 있으면 파싱해 구체적 상승 벡터를 랭킹한다(생성 전용 — 제안만, 실행 아님).
            if os_class == "linux":
                self._privesc_analyze_stage(report)
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("privesc_error", error=str(e))

    def _privesc_analyze_stage(self, report: OrchestrationReport) -> None:
        """③ 폐루프 후보 선정 — findings 에 privesc 열거 출력(sudo -l·SUID·getcap)이 있으면
        파싱해 구체적 상승 벡터를 랭킹하고 수동 제안으로 surface 한다. 생성 전용(실행 아님).
        벡터의 '실제 실행 → root 확인 → world 권한레벨 전이 → 재열거'(폐루프 발사)는 사용자
        리포의 실행 스테이지(target_shell) 몫 — 여기선 후보·계획만 만든다."""
        corpus = "\n".join(f.output for f in (report.enum_findings + report.llm_findings)
                           if f.output)
        if not corpus.strip():
            return
        from .privesc_analyze import analyze_enum, render_vectors
        vectors = analyze_enum(corpus)
        if not vectors:
            return
        report.privesc_vectors = vectors
        suggestion = render_vectors(vectors)
        if suggestion not in report.manual_suggestions:
            report.manual_suggestions.append(
                "# 권한상승 벡터(열거 출력 자동 분석 — 권한 확인 자산 전용):\n" + suggestion)
        self.audit.event("privesc_vectors", count=len(vectors),
                         kinds=[v.kind for v in vectors[:5]])

    def _world_fingerprint(self, report: OrchestrationReport) -> tuple:
        """스윕 간 '상태 성장' 판정용 지문. 관측·크리덴셜·서비스·권한이 늘면 달라진다.
        스윕 후 지문이 그대로면 더 진전이 없다는 뜻이라 반복을 조기 종료한다(유한)."""
        w = self.world
        return (
            len(report.enum_findings),
            len(report.llm_findings),
            len(w.creds) if w else 0,
            len(w.services) if w else 0,
            len(w.loot) if w else 0,
            len(w.learned) if w else 0,
            len(w.proven_vulns) if w else 0,
            w.access_level if w else "none",
            # [S1] 웹앱 식별·버전 보강·vhost 등록도 '성장'으로 인정 — 이들만 자란 스윕이
            # '정체'로 오판돼 조기 종료되면 그걸 소비하는 스테이지가 영영 안 돌던 결정성 버그 교정.
            w.web_product if w else "",
            w.web_version if w else "",
            len(self.hosts_map or {}),
        )

    def _prepare_crack(self, report: OrchestrationReport) -> None:
        """enum/LLM 출력·크리덴셜 볼트에서 해시를 수집해 크래킹 명령을 자동 준비한다.
        생성 전용 — 크래킹은 사용자 환경에서 실행. 해시가 없으면 조용히 생략."""
        # 실행 원시출력에서 수집한 해시(요약 전 — _attempt 에서 스캔) + 요약출력 보강
        hashes: list[str] = list(getattr(self, "_found_hashes", []))
        for f in report.enum_findings + report.llm_findings:
            if f.output:
                hashes.extend(crack_scan(f.output))
        for p in report.host.ports if report.host else []:
            for sc in p.scripts.values():
                hashes.extend(crack_scan(sc))
        # 크리덴셜 볼트의 NT 해시(PtH)도 크래킹 후보
        if self.vault is not None:
            for c in self.vault.creds:
                nt = getattr(c, "nt_hash", None)
                if nt:
                    # PtH NT 해시는 'LM:NT' 형식일 수 있어 NT 부분만 사용
                    hashes.append(nt.split(":")[-1])
        if not hashes:
            return
        try:
            from . import crack
            report.crack_jobs = crack.prepare(hashes)
            if report.crack_jobs:
                self.audit.event("crack_prepared", jobs=len(report.crack_jobs))
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("crack_error", error=str(e))

    def _repetition_warning(self, report: OrchestrationReport, cmd: str) -> str:
        """이 명령이 '이전에 실패한 같은 종류의 시도'와 겹치면 경고 문자열(없으면 "").
        종류 판정은 repetition.signature(바이너리+플래그, 대상·워드리스트 등 가변값 무시).
        반복을 막지는 않는다 — 사람이 판단하도록 알리기만 한다(AutoPentester Repetition Identifier)."""
        from . import repetition
        sig = repetition.signature(cmd)
        failed = {c for c, _ in (getattr(report, "blockers", []) or [])}
        for i, f in enumerate(report.enum_findings + report.llm_findings, 1):
            if f.command in failed and repetition.signature(f.command) == sig:
                why = ""
                for c, d in report.blockers:
                    if c == f.command:
                        why = f"({d.kind}: {d.label})"
                        break
                return f"⟳ 앞서 실패한 같은 종류의 시도와 겹침 {why} — 다른 도구·옵션·경로 권장"
        return ""

    def _repetition_saturated(self, report: OrchestrationReport, cmd: str, limit: int = 3) -> bool:
        """같은 '종류'(repetition.signature: 바이너리+플래그)의 시도가 이미 limit 회 이상
        '실패'했으면 True — 더 실행하지 말고 건너뛴다(한 경로에 매달리는 산발 반복 억제).
        _repetition_warning 이 '1회 겹침'을 경고만 한다면, 이건 '누적 실패'를 집중도 관점에서
        차단한다(예산·시간 절약). 성공/유의미 출력이 있던 종류는 세지 않는다."""
        from . import repetition
        sig = repetition.signature(cmd)
        failed = {c for c, _ in (getattr(report, "blockers", []) or [])}
        n = sum(1 for f in (report.enum_findings + report.llm_findings)
                if f.command in failed and repetition.signature(f.command) == sig)
        return n >= limit

    def _apply_command_fix(self, finding: EnumFinding, cmd: str, sres, vrep):
        """Results Verifier(AutoPentester): 범위 밖으로 거부될 명령의 타겟 자리표시자·오타를
        바인딩 타겟으로 자동 교정해 복구 시도. 교정본이 검증·범위를 다시 통과하면 그것으로 교체.
        반환: (cmd, sres, vrep) — 교정 성공 시 교정본, 아니면 원본 그대로. (_gate 에서 분리)"""
        if not (self.fix_commands and not sres.auto_allowed):
            return cmd, sres, vrep
        fixed, why = command_fixer.correct_target(cmd, self.guard)
        if fixed == cmd:
            return cmd, sres, vrep
        try:
            fres = self.guard.inspect_command(fixed, hosts_map=self.hosts_map)
            fvrep = validate(fixed)
        except ScopeViolation:
            return cmd, sres, vrep
        if fres.auto_allowed and fvrep.ok and not fvrep.review:
            self.audit.event("verifier_fixed", original=cmd, fixed=fixed, reason=why)
            finding.command = fixed
            finding.note = (finding.note + " · " if finding.note else "") + f"✎ 자동교정({why})"
            return fixed, fres, fvrep
        return cmd, sres, vrep

    def _gate(self, report: OrchestrationReport, findings: list[EnumFinding],
              cmd: str, phase: str) -> EnumFinding | None:
        """3관문(도구·검증·범위·승인)을 순차 수행(공유상태 변경은 단일 스레드).
        통과하면 '실행 대상' finding 반환, 아니면 사유를 기록하고 None."""
        finding = EnumFinding(command=cmd, phase=phase)
        findings.append(finding)
        self.audit.event("proposed", cmd=cmd, phase=phase)
        gs = report.gate_stats
        gs["proposed"] += 1

        binary = binary_of(cmd)
        if binary and not self.is_tool_available(binary):
            finding.note = f"건너뜀: '{binary}' 미설치"
            finding.skipped = True
            gs["tool_missing"] += 1
            self.audit.event("skipped", cmd=cmd, reason="tool-missing", binary=binary)
            return None
        vrep: ValidationReport = validate(cmd)
        # 셸 비경유 실행기에선 파이프·리다이렉트가 인자로 넘어가 조용히 오작동한다 → 실행 전 거부.
        # 단, 동적·원격 실행(EXEC_RISK review: curl|bash 등)은 기존 경로가 '수동 제안'으로
        # 강등해 사람이 대안과 함께 보게 하므로 여기서 가로채지 않는다.
        if vrep.ok and not vrep.review and not getattr(self.runner, "shell", False):
            ops = shell_operators(cmd)
            if ops:
                finding.note = ("검증 실패: 셸 연산자(" + " ".join(dict.fromkeys(ops))
                                + ") — 셸 비경유 실행에서 동작 안 함(--sandbox 사용 시 가능)")
                gs["rejected_validate"] += 1
                self.audit.event("rejected", cmd=cmd, stage="validate",
                                 errors=["shell-operators: " + " ".join(ops)])
                return None
        if not vrep.ok:
            finding.note = "검증 실패: " + "; ".join(str(i) for i in vrep.errors)
            gs["rejected_validate"] += 1
            self.audit.event("rejected", cmd=cmd, stage="validate",
                             errors=[str(i) for i in vrep.errors])
            return None
        try:
            sres: CommandScopeResult = self.guard.inspect_command(cmd, hosts_map=self.hosts_map)
        except ScopeViolation as e:
            finding.note = f"범위 오류: {e}"
            gs["rejected_scope"] += 1
            self.audit.event("rejected", cmd=cmd, stage="scope", reason=str(e))
            return None
        cmd, sres, vrep = self._apply_command_fix(finding, cmd, sres, vrep)
        # 집중도: 같은 종류 시도가 이미 여러 번 실패했으면 실행 않고 건너뜀(산발 반복 억제).
        if self._repetition_saturated(report, cmd):
            finding.note = ((finding.note + " · " if finding.note else "")
                            + "⟳ 반복 억제: 같은 종류 시도가 여러 번 실패 — 건너뜀(다른 경로 권장)")
            gs["repetition_skipped"] = gs.get("repetition_skipped", 0) + 1
            self.audit.event("repetition_skipped", cmd=cmd)
            entry = cmd + "   # (반복 억제 — 필요 시 수동 검토)"
            if entry not in report.manual_suggestions:
                report.manual_suggestions.append(entry)
            return None
        warn = self._repetition_warning(report, cmd)
        if warn:
            from . import ui
            finding.note = (finding.note + " · " if finding.note else "") + warn
            if not self.quiet:
                print("  " + ui.mark_warn(warn))   # 승인 전 경고(초보자: 같은 실패 반복 주의)
            self.audit.event("repetition_warn", cmd=cmd, detail=warn)
        if not self.approver(cmd, vrep, sres):
            review = [i.message for i in vrep.review]
            if review:
                # 동적·원격 코드 실행: 자동실행 대신 수동 제안으로 강등(사람이 내용 확인)
                finding.note = "미승인(실행위험): " + "; ".join(review)
                gs["denied_review"] += 1
                from .approval import safer_alternative
                alt = safer_alternative(cmd)
                entry = cmd + "   # (실행위험 — 내용 확인 후 수동)" + (f" · 대안: {alt}" if alt else "")
                if entry not in report.manual_suggestions:
                    report.manual_suggestions.append(entry)
            else:
                finding.note = "미승인(범위밖/사용자 거부)"
                gs["denied_scope"] += 1
            self.audit.event("denied", cmd=cmd, in_scope=sres.auto_allowed, review=review)
            self._record_observation(finding)
            return None
        return finding

    def _record_observation(self, finding: EnumFinding) -> None:
        """사람 관찰 입력(선택). 건너뛴 명령 대신 사람이 브라우저 등으로 직접 확인한 내용을
        '사람 관찰'로 표시해 남긴다 — 에이전트가 검증한 결과와 섞이지 않고, 다음 분석·명령
        생성의 맥락(관측 목록)에는 들어간다. 입력이 없으면 아무것도 하지 않는다."""
        if self.observer is None:
            return
        try:
            text = (self.observer(finding.command) or "").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not text:
            return
        text = text[:500]
        finding.output = f"[사람 관찰] {text}"
        finding.note = (finding.note + " · " if finding.note else "") + "👁 사람 관찰 기록"
        if self.world is not None:
            self.world.add_loot(f"사람 관찰: {text[:80]}", source="사람 관찰")
        self.audit.event("human_observation", cmd=finding.command, text=text)

    def _process(self, report: OrchestrationReport, finding: EnumFinding, out) -> None:
        """실행 결과를 반영(파싱·플래그/해시/크리덴셜 스캔). 공유상태를 변경하므로
        반드시 단일 스레드에서, 제출 순서대로 호출한다(병렬 실행과 분리)."""
        cmd = finding.command
        finding.ran = out.launched
        report.gate_stats["executed" if out.launched else "run_failed"] += 1
        if not out.launched:
            finding.note = f"실행 실패: {out.error}"
            self.audit.event("executed", cmd=cmd, launched=False, error=out.error)
            self._diagnose(report, finding, out)   # 실행 실패도 원인 분류(환경 문제)
            return
        finding.output = summarize_tool_output(cmd, out.stdout, out.stderr)
        if len(finding.output) > _MAX_FINDING_OUTPUT:   # 마라톤 세션 메모리 상한(명시적)
            finding.output = finding.output[:_MAX_FINDING_OUTPUT] + "…(출력 상한 초과 — 생략)"
        # 분석 전용 원본 보존 — 핑거프린트/searchsploit 매칭이 요약 손실을 겪지 않도록(요약과 분리).
        raw = (out.stdout or "")
        finding.raw_output = raw[:_MAX_RAW_OUTPUT] if len(raw) > _MAX_RAW_OUTPUT else raw
        self.audit.event("executed", cmd=cmd, launched=True,
                         returncode=out.returncode, summary=finding.output)
        # 실패 진단(사람 확인용) — 404/403/타임아웃 등 원인 분류. 자동 재공격 아님.
        self._diagnose(report, finding, out)
        # 플래그 스캔 — 출력에서 플래그 획득(플랫폼별 종류/접두 적용)
        for hit in scan_flags(cmd, out.stdout, flag_kind=self.flag_kind,
                              prefixes=self.flag_prefixes):
            if hit.value not in {f.value for f in report.flags}:
                report.flags.append(hit)
                # 출처 검증(실행 트레이스 기반) — 이 플래그를 만든 명령을 분류해 기록.
                prov = self._classify_flag(report, hit, cmd, finding.phase)
                report.flag_provenance.append(prov)
                note_mark = f"🚩 {hit.kind} flag"
                if prov.verdict != "exploit-derived":
                    note_mark += f"({prov.label})"
                finding.note = (finding.note + " " if finding.note else "") + note_mark
                self.audit.event("flag_found", kind=hit.kind, value=hit.value, cmd=cmd,
                                 provenance=prov.verdict)
                if self.world is not None:
                    self.world.add_flag(hit.kind, hit.value)
        # 해시 스캔 — 원시출력(요약 전)에서 크래킹 대상 해시 수집(크래킹 자동 준비용)
        for hv in crack_scan(out.stdout):
            if hv not in self._found_hashes:
                self._found_hashes.append(hv)
                self.audit.event("hash_found", cmd=cmd, hash=hv[:24])
                if self.world is not None:
                    self.world.add_loot(f"해시: {hv[:40]}{'…' if len(hv) > 40 else ''}",
                                        source=binary_of(cmd, strip_path=True))
        # 크리덴셜 자동 수확 — 원시출력에서 고신뢰 평문 자격 추출. 월드엔 모두 반영,
        # 실행 볼트엔 셸-안전한 값만(신뢰불가 출처 인젝션 차단). A1 재진입을 활성화.
        self._harvest_creds(out.stdout, cmd, finding)
        # vhost 자동 등록 — 리다이렉트(→ http://connected.htb/)에서 발견한 호스트명을
        # '타겟 IP' 로 스코프 해석맵에 자동 등록(이후 그 vhost 명령이 범위 안으로 인식됨).
        self._maybe_register_vhost(report, finding.output)

    def _maybe_register_vhost(self, report: OrchestrationReport, text: str) -> None:
        """리다이렉트 출력에서 vhost 를 발견하면 타겟 IP 로 스코프 해석맵(hosts_map)에
        자동 등록한다 → 프롬프트·스킵 없이 진행. OS 이름해석(/etc/hosts)은 권한 있으면
        자동 추가, 없으면 '조용한 반복 실패' 대신 1회 또렷한 안내를 남긴다.
        스코프는 '타겟 IP' 로만 묶으므로 범위를 넓히지 않는다(안전)."""
        if not text or self.guard.bound_target is None:
            return
        ip = str(self.guard.bound_target)
        for m in _REDIRECT_HOST_RE.finditer(text):
            host = m.group(1).lower().rstrip(".")
            if (not host or host in self._vhost_seen or not re.search(r"[a-z]", host)
                    or (self.hosts_map or {}).get(host)):
                continue
            self._vhost_seen.add(host)
            if self.hosts_map is None:
                self.hosts_map = {}
            self.hosts_map[host] = ip   # vhost → 타겟 IP (스코프 in-scope 로 인식)
            self.audit.event("vhost_registered", host=host, ip=ip)
            self._ensure_name_resolution(report, host, ip,
                                         getattr(self, "_hosts_path", "/etc/hosts"))

    def _ensure_name_resolution(self, report: OrchestrationReport, host: str, ip: str,
                                hosts_path: str = "/etc/hosts") -> None:
        """가능하면 /etc/hosts 에 자동 등록(쓰기 권한 있을 때만 — 보통 root 실행). 권한이
        없으면 조용히 실패하지 않고, '한 번만' 실행할 명령을 수동 제안에 1회 남긴다."""
        import os as _os
        line = f"{ip} {host}"
        try:
            existing = ""
            if _os.path.exists(hosts_path):
                with open(hosts_path, encoding="utf-8", errors="replace") as f:
                    existing = f.read()
            if re.search(rf"(?m)^\s*\S+\s+.*\b{re.escape(host)}\b", existing):
                return   # 이미 등록됨
            if _os.access(hosts_path, _os.W_OK):   # 권한 있음(root) → 자동 추가
                with open(hosts_path, "a", encoding="utf-8") as f:
                    f.write(f"{line}\n")
                self.audit.event("etc_hosts_added", host=host, ip=ip)
                return
        except OSError:
            pass
        hint = (f"이름해석 1회 설정(그러면 {host} 명령이 완전 자동 진행): "
                f"echo '{line}' | sudo tee -a /etc/hosts")
        if hint not in report.manual_suggestions:
            report.manual_suggestions.append(hint)

    def _classify_flag(self, report: OrchestrationReport, hit, cmd: str, phase: str):
        """출처 분류 + 작업공간 보정.
        - 에이전트가 쓴 스크립트 본문에 플래그 문자열이 그대로 있으면 '로컬 유래'(지어낸 값일 수 있음)
        - 첨부파일만 있는 문제(열린 포트 없음)에서 files/ 를 읽은 로컬 명령의 출력은 풀이 결과로 인정"""
        # 외부/학습 자료(웹학습·ingest 노트)에 플래그가 그대로 있으면 looked-up(라이트업·검색 의심)
        in_external = self._flag_in_external_notes(hit.value)
        prov = _prov.classify(hit.kind, hit.value, cmd, phase, in_external=in_external)
        if prov.verdict in ("reasoning-only", "looked-up"):
            return prov
        ws = self.workspace
        if ws is None:
            return prov
        for rel in ws.written:
            try:
                with open(ws.resolve(rel), encoding="utf-8", errors="replace") as f:
                    if hit.value in f.read():
                        prov.verdict = "local-derived"
                        prov.reason = f"에이전트가 작성한 {rel} 본문에 플래그 문자열 포함 — 지어낸 값일 수 있음"
                        return prov
            except OSError:
                continue
        offline = report.host is not None and not report.host.open_ports
        if offline and prov.verdict == "local-derived" and "files/" in cmd:
            prov.verdict = "exploit-derived"
            prov.reason = "첨부파일 분석 출력에서 추출(오프라인 문제)"
        return prov

    def _flag_in_external_notes(self, value: str) -> bool:
        """플래그 값이 웹학습·ingest 등 '외부에서 가져온' 노트 본문에 그대로 있는가(looked-up 판정).
        사용자가 직접 올린 라이트업(ingest)이라도, 플래그가 거기 적혀 있었다면 공략이 아니라
        '본 것'이므로 사람이 확인하도록 표시한다. 번들 시드(공략 흔적 없는 레퍼런스)는 제외."""
        if not value or self.kb is None:
            return False
        try:
            notes = self.kb.external_notes()
        except Exception:   # noqa: BLE001 — 분류 보조 실패가 본 작업을 막지 않음
            return False
        return any(value in n for n in notes)

    def _diagnose(self, report: OrchestrationReport, finding: EnumFinding, out) -> None:
        """실패를 원인별로 분류해 finding 비고에 덧붙이고 report.blockers 에 기록한다.
        '대상 응답'(404/403…)과 '환경/도구/네트워크 문제'를 구분해 사람이 판단하게 한다.
        자동 재시도·경로 변경은 하지 않는다(판단 재료만 제공)."""
        try:
            diag = diagnostics.diagnose(finding.command, out)
        except Exception as e:   # noqa: BLE001 — 진단 실패가 본 작업을 막지 않음
            self.audit.event("diagnose_error", cmd=finding.command, error=str(e))
            return
        if diag is None:
            return
        tag = f"[{diag.kind}] {diag.label}"
        finding.note = (finding.note + " · " if finding.note else "") + tag
        report.blockers.append((finding.command, diag))
        self.audit.event("diagnosis", cmd=finding.command, category=diag.category,
                         is_target=diag.is_target)

    def _safe_run(self, cmd: str) -> "RunOutput":
        """runner.run 을 예외로부터 보호. 어떤 러너 예외도 실패 RunOutput 으로 흡수해
        한 명령의 실패가 라운드/배치 전체를 깨지 않도록 한다(병렬 map 보호 포함)."""
        try:
            return self.runner.run(cmd, timeout=180)
        except Exception as e:   # noqa: BLE001
            self.audit.event("run_exception", cmd=cmd, error=f"{type(e).__name__}: {e}")
            return RunOutput(cmd, error=f"러너 예외: {type(e).__name__}: {e}", returncode=-1)

    def _attempt(self, report: OrchestrationReport, findings: list[EnumFinding],
                 cmd: str, phase: str = "enum") -> None:
        """순차 실행: 게이트 → (통과 시) 실행 → 결과 처리."""
        finding = self._gate(report, findings, cmd, phase)
        if finding is None:
            return
        if self.dry_run:   # 계획 미리보기 — 게이트까지 통과했으나 실행하지 않음
            finding.note = (finding.note + " · " if finding.note else "") + "dry-run: 제안만(미실행)"
            report.gate_stats["dry_run"] = report.gate_stats.get("dry_run", 0) + 1
            return
        out = self._safe_run(finding.command)
        self._process(report, finding, out)

    def _attempt_batch(self, report: OrchestrationReport, findings: list[EnumFinding],
                       cmds: list[str], phase: str) -> list[EnumFinding]:
        """병렬 실행: 게이트를 '순차로' 통과시킨 뒤, 통과한 명령의 runner.run 만
        스레드풀로 동시 실행하고, 결과 처리는 다시 '제출 순서대로 단일 스레드'로
        수행한다 → 공유상태 경쟁 없음·결정적 순서 보존. 게이트 통과 finding 목록 반환."""
        gated: list[EnumFinding] = []
        for cmd in cmds:
            f = self._gate(report, findings, cmd, phase)
            if f is not None:
                gated.append(f)
        if not gated:
            return []
        if self.dry_run:   # 계획 미리보기 — 게이트 통과분을 실행하지 않고 표시만
            for f in gated:
                f.note = (f.note + " · " if f.note else "") + "dry-run: 제안만(미실행)"
            report.gate_stats["dry_run"] = report.gate_stats.get("dry_run", 0) + len(gated)
            return gated
        from concurrent.futures import ThreadPoolExecutor
        workers = max(1, min(self.max_parallel, len(gated)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            # map 은 입력 순서대로 결과를 돌려주므로 결정성 유지(I/O 만 병렬).
            # _safe_run 이 각 작업 예외를 흡수 → 한 명령 실패가 배치 전체를 깨지 않음.
            outs = list(ex.map(lambda f: self._safe_run(f.command), gated))
        for f, out in zip(gated, outs):
            self._process(report, f, out)
        return gated
