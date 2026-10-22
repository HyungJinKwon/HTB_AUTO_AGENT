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
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .exploit_modules import ExploitModule
    from .scheduler import StageScheduler

from . import command_fixer, diagnostics, flag_assess, preparations, results_verify, reversing
from . import provenance as _prov
from .audit import NullAudit
from .command_validator import ValidationReport, shell_operators, validate
from .crack import scan_hashes as crack_scan
from .creds import CredentialVault
from .creds_harvest import harvest as harvest_creds
from .creds_harvest import is_safe_for_cmd
from .flag import FlagHit
from .flag import scan as scan_flags
from .foothold import FootholdMixin
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
# raw HTTP 리다이렉트 헤더에서 vhost 추출: "Location: http://enigma.htb/" → enigma.htb
# (웹 프로브가 -i/-I 로 헤더를 내면 302 Location 으로 vhost 를 자동 발견 — 요약 화살표 없이도).
_LOCATION_HOST_RE = re.compile(r"(?im)^\s*location:\s*https?://([A-Za-z0-9.-]+?\.[A-Za-z]{2,})(?:[:/]|\s|$)")
# 임의 도구 출력(NFS PDF·배너·본문)에 박힌 HTB 랩 vhost 토큰: "mail001.enigma.htb" 등.
# .htb/.local 로 끝나는 호스트명만 — scope_guard 의 랩 vhost 특수취급과 동일(외부 도메인 비대상).
_HTB_VHOST_RE = re.compile(r"\b((?:[A-Za-z0-9-]+\.)+(?:htb|local))\b", re.I)


@dataclass
class EnumFinding:
    command: str
    ran: bool = False
    note: str = ""
    output: str = ""        # 표시·저장용 요약(손실 가능) — summarize_tool_output 결과
    phase: str = "enum"
    skipped: bool = False   # 도구 미설치로 시도조차 안 함 — 예산(max_enum/max_llm)을 쓰지 않는다
    # [S5-1] KB 열거 예산(max_enum)에 계상할지. 결정적 소비 스테이지(핑거프린트·버전프로브·
    # 익스조회·웹비밀)는 스케줄러의 제품/호스트별 멱등 가드로 이미 유한하므로 False 로 두어
    # KB enum 예산을 잠식하지 않게 한다(과거엔 이들이 max_enum 을 선점해 _enum_round 가 영영
    # 안 돌던 HIGH 버그). 도구 미설치(skipped)와는 독립.
    budgeted: bool = True
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
    discovered_cve: list[str] = field(default_factory=list)  # 제품→CVE 자동발견(NVD 역질의)
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
    # 자동 준비된 측면 이동 후보(수확 크리덴셜/해시 → 열린 다른 서비스 재사용·PtH — 생성만, 사용자 실행)
    lateral_candidates: list = field(default_factory=list)  # list[lateral.LateralCandidate]
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
    # [A6] LLM-심판(opt-in·advisory) — 증거가 '공략 달성'을 뒷받침하는지 조언. judge.JudgeVerdict|None.
    # 규칙 판정(goal_reached·provenance)을 덮지 않음(보조 의견).
    judge_verdict: object | None = None
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

    def summary(self, verbose: bool = False) -> str:
        from . import report_view
        return report_view.render_summary(self, verbose=verbose)

    def glance(self) -> str:
        """맨 끝 '한눈에 보기' — report_view.render_glance 로 위임(렌더링은 report_view)."""
        from . import report_view
        return report_view.render_glance(self)


class Orchestrator(FootholdMixin):
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
                 catch_revshell: bool = False,
                 poc_commands: "list[str] | None" = None,
                 poc_dir: str = "",
                 fetch_pocs: bool = False,
                 judge: bool = False,
                 priv_env: bool = False,
                 workspace=None):
        self.guard = guard
        self.runner = runner
        # [env-auto] 권한(root/sudo) 로컬 환경조작 옵트인 — sudo NFS 마운트·/etc/hosts 쓰기.
        # 기본 OFF(—full-auto 에 포함 안 함). rootless(libnfs·Host헤더)로 안 되는 경우의 폴백 전용.
        self.priv_env = priv_env
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
        from .clues import ClueStore
        self.clues = ClueStore()   # [lab:clues] 교차단계 단서 누적(LLM 컨텍스트 되먹임)
        self._phase_llm_rounds: dict[str, int] = {}   # [lab:tiering] 단계별 LLM 라운드 수(티어 상승)
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
        # 리버스셸 수신 발판(opt-in). 켜지면 _acquire_session 이 준비된 revshell(lhost/lport)로
        # 소켓 리스너를 띄워 콜백을 받는다(RCE 실행 표면). 기본 OFF — 기본 흐름에 소켓 블로킹 없음.
        self.catch_revshell = catch_revshell
        self.judge = judge   # [A6] LLM-심판(opt-in·advisory)
        self._exploit_looked_up: set[str] = set()   # 제품별 공개 익스 조회 1회 가드
        self._version_probed: set[str] = set()       # 제품별 버전 노출 프로브 1회 가드
        self._web_secret_probed: set[str] = set()     # 웹 노출 비밀/백업 열거 1회 가드(베이스별)
        self._web_fp_probed: set[str] = set()          # vhost 결정적 핑거프린트 1회 가드
        self._vhost_brute_probed: set[str] = set()     # 도메인별 서브도메인 브루트 1회 가드
        self.poc_commands = poc_commands or []
        # 내장 익스 모듈(공개 PoC 오케스트레이션) — 사용자 선조달 PoC 디렉터리(선택) + 활성 모듈 핸들.
        self.poc_dir = poc_dir
        # 공개 PoC 자동 조달(옵트인) — 레지스트리 선언 출처에서만. --full-auto 가 켠다.
        self.fetch_pocs = fetch_pocs
        self._active_exploit_module: "ExploitModule | None" = None   # _consider_builtin_exploit 가 매칭 시 세팅(발판 캡처용)
        self._poc_fetch_fn = None            # 테스트/대체 주입(실 네트워크 없이 조달 흉내)
        self._cve_lookup_fn = None           # 테스트/대체 주입(searchsploit --cve 출력 흉내)

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
        self._verify_retried: set[str] = set()   # [T1-a] 출력구동 교정을 이미 건 원 명령(1회 제한)
        self._verify_budget_left = 8             # [T1-a] 전역 교정 재시도 상한(예산 보호)
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
            self._analyze_offline_files(report)   # [G2] export-first 정적 리버싱
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
            # [S3] 결정적 소비 스테이지의 의존 선언형 스케줄러(런당 1회 구성, _seen 은 스윕 간 유지).
            self._consume_sched = self._build_consume_scheduler(report, host)
            while sweeps_run < sweep_cap:
                if self._goal_reached(report) or self._time_up():
                    break
                before_fp = self._world_fingerprint(report)
                # 지금까지의 출력에서 취약점(CVE/CWE·버전 매칭)을 먼저 반영 — 학습·분석·
                # 명령 생성이 '확인 취약점'을 보고 판단하도록(이전엔 루프가 끝난 뒤에야 계산)
                self._run_vuln(report, host, target)
                # [S3] 결정적 소비 스테이지(핑거프린트→버전프로브→익스조회→웹비밀)를 의존 선언형
                # 스케줄러로 '입력이 자란 것만, 생산자→소비자 순서로, 지역 고정점까지' 실행한다.
                # S1 의 수동 재배치·각 스테이지의 _*_probed 가드가 암묵적으로 하던 스케줄링을
                # 명시적·테스트 가능한 1급 객체로 승격(본체·멱등 가드는 불변). 무해/생성 전용 경계 유지.
                self._consume_sched.run_to_fixpoint(
                    lambda: self._goal_reached(report) or self._time_up())
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
                    # [S5-4] 진행 판정은 '실제로 실행된'(비skipped) finding 기준 — 도구 미설치
                    # (skipped)만 생긴 단계를 '진행'으로 오표기하지 않게.
                    def _ran_total() -> int:
                        # LLM finding 도 enum 과 동일하게 skipped(도구 미설치) 제외 — 과거엔
                        # len(llm_findings) 라 '설치 안 된 도구만 제안한 단계'도 '진행'으로 오표기.
                        return (sum(1 for f in report.enum_findings if not f.skipped)
                                + sum(1 for f in report.llm_findings if not f.skipped))
                    phase_before = _ran_total()
                    for _rnd in range(self.max_rounds):
                        added = self._enum_round(
                            report, host, prof, target, seen_cmds,
                            self.max_enum - self._spent(report.enum_findings, self._enum_base, key),
                            key)
                        if (use_llm and not self._goal_reached(report)
                                and not self._cost_capped(report)):
                            added += self._llm_round(
                                report, host, prof, target, seen_cmds,
                                self.max_llm - self._spent(report.llm_findings, self._llm_base, key),
                                key)
                        if added == 0 or self._goal_reached(report) or self._time_up():
                            break
                    grew = _ran_total() > phase_before
                    if grew and key not in phases_run:
                        phases_run.append(key)
                    # 한 번이라도 '진행'한 단계는 이후 스윕에서 새 명령이 없어도 '진행' 유지
                    if report.phase_status.get(key) != "진행":
                        report.phase_status[key] = ("대기(" + reason + ")" if not met
                                                    else ("진행" if grew else "점검함"))
                    self._run_vuln(report, host, target)   # 다음 단계가 새 취약점을 보도록
                # [S3] enum 단계가 vhost·웹본문으로 제품을 '이번 스윕에' 키웠으면, 입력이 바뀐
                # 소비 스테이지만 스케줄러가 생산자→소비자 순서로 다시 돌려 같은 스윕에 반영
                # (다음 스윕까지 밀리지 않게). _seen 덕에 입력 불변 스테이지는 no-op.
                self._consume_sched.run_to_fixpoint(
                    lambda: self._goal_reached(report) or self._time_up())
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
        except Exception as e:   # noqa: BLE001 — [F3 불변식] 스윕 중 예기치 못한 예외(_process
            # 스캐너·파싱 등)가 run() 밖으로 새면 _persist 가 생략돼 진행 상태가 통째로 유실된다
            # (재개 불가). 감사에 남겨 침묵 드롭을 피하고, 저장 경로(PHASE 4)로 진행한다.
            self.audit.event("sweep_error", error=f"{type(e).__name__}: {e}", sweeps=sweeps_run)
            report.message += f"⚠ 스윕 중 오류({type(e).__name__}) — 진행분까지 저장(감사 로그 참조). "
        report.timed_out = self._time_up()
        report.elapsed_sec = round(self._clock() - self._start, 1)
        if report.timed_out:
            # 시간 예산 소진도 중단과 같은 경로: 남은 단계 생략, 상태 저장, 네트워크 수집 생략
            interrupted = True
            self.audit.event("timed_out", budget_min=self.time_budget,
                             elapsed_sec=report.elapsed_sec, sweeps=sweeps_run)

        # ── PHASE 3.7: VULN (CVE/CWE 탐지 + 매핑) — 최종 출력까지 반영 ──
        try:
            self._run_vuln(report, host, target)
        except Exception as e:   # noqa: BLE001 — 최종 취약점 반영 실패가 저장·리포트를 막지 않음(F3)
            self.audit.event("vuln_error", error=f"{type(e).__name__}: {e}")

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
            # [제품→CVE 자동발견] 탐지된 제품/버전으로 NVD 를 역질의해, KB 룰이 없는 신종
            # CVE 도 자동으로 수면 위로 올린다(기존엔 '이미 아는 CVE ID' 만 조회 → 룰 없는
            # 제품은 버전을 정확히 탐지하고도 '매칭 없음'으로 묻혔다). 발견은 자동, 실행은
            # 아니다 — 발견 CVE 는 아래 enrich 를 거쳐 리포트에 '제안'으로만 노출(생성 경계).
            try:
                for prod, ver in self._discovery_targets():
                    for info in self.enricher.discover_by_product(prod, ver):
                        if info.id not in report.discovered_cve:
                            report.discovered_cve.append(info.id)
                        if info.id not in all_cves:
                            all_cves.append(info.id)
                if report.discovered_cve:
                    self.audit.event("cve_discovered", cves=report.discovered_cve)
            except Exception as e:   # noqa: BLE001 — 발견 실패는 진행 방해 금지
                self.audit.event("discover_error", error=str(e))
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
        # [감사 F3] 루프-후 생성/준비·평가 스테이지는 예기치 못한 예외가 나도 run() 밖으로
        # 던지지 않는다 — 여기서 터지면 PHASE 4 의 _persist 가 생략돼 '지금까지 실행한 모든
        # 진행 상태'가 통째로 유실된다(재개 불가). 예외는 감사 로그에 남겨 침묵 드롭을 피하고
        # (정직성 §3), 리포트·저장(PHASE 4)으로 반드시 진행한다. 명령 실행 자체는 _safe_run 이
        # 이미 흡수하므로, 여기서 잡히는 건 파싱·준비·평가 로직의 예외다.
        post_stage_error = ""
        try:
            if not interrupted:
                self._refresh_exploit_shortlist(report, host)
            # ── PHASE 3.9: 리버스쉘 자동 준비 (공격자 IP 확보 시) ──
            # ⚠️ 발판 '시도 전에' 준비해야 한다 — _foothold_stage 의 리버스셸 수신 경로가
            # report.revshell_lhost/lport 를 읽는데, 이 함수가 유일한 writer 이기 때문이다.
            # 과거엔 발판 뒤에 준비돼 lhost 가 항상 "" → --catch-revshell 이 구조적으로
            # 무력화됐다(생성 전용이라 발판보다 먼저 돌아도 안전·부작용 없음).
            self._prepare_revshells(report)
            # PHASE 3.9 직전: PoC 실행(3단계) → 웹 RCE 발판 → exploit-exec 발판(1단계)
            if self.exploit_exec and not interrupted:
                self._nfs_harvest_stage(report, host)     # [env-auto] NFS export 마운트·수확(자격/키/플래그)
                self._consider_builtin_exploit(report, host)  # 내장 익스 모듈 매칭 → PoC 조달·큐잉
                self._exploit_run_stage(report, host)     # 3단계: PoC 실행 → 자격·발판 URL 캡처
                self._foothold_stage(report, host)        # 웹 RCE 발판·리버스셸 → 자격수확 → 플래그
                self._mail_harvest_stage(report, host)    # 수확 자격으로 IMAP/POP3 로그인 → 본문서 다음 자격 수확
                self._exploit_exec_stage(report, host)    # 1단계: SSH 자격 → 플래그 → privesc

            # ── PHASE 3.95: AWS/S3 열거 자동 준비 (호스트명/도메인 확보 시) ──
            # 버킷 후보·비인증 점검을 자동 생성. AWS 엔드포인트는 타겟 범위 밖이라
            # 실행하지 않고 준비만 한다(리버스쉘과 동일한 '생성 전용' 안전 경계).
            self._prepare_cloud(report)

            # ── PHASE 3.96: 권한상승 플레이북 자동 준비 (OS 식별 시) ──
            # OS 에 맞는 포스트-익스플로잇 권한상승 열거·점검 체크리스트를 자동 생성.
            # 대상 셸 안에서 실행하는 명령이라 에이전트는 준비만(생성 전용) 한다.
            self._prepare_privesc(report, prof)

            # ── PHASE 3.965: 측면 이동 후보 자동 준비 (크리덴셜/해시 수확 시) ──
            # 수확한 user:pass·NT 해시를 '열린 다른 서비스'(SSH/SMB/WinRM/...)에 재사용·PtH 하는
            # 후보를 생성한다. 생성 전용 — 사용자가 권한 확인 자산에서 직접 실행(에이전트 발사 없음).
            self._prepare_lateral(report)

            # ── PHASE 3.97: 해시 크래킹 자동 준비 (출력/볼트에서 해시 수집 시) ──
            # 캡처된 해시를 식별해 john/hashcat 명령을 자동 생성. 크래킹은 무겁고
            # 워드리스트가 필요해 에이전트는 준비만(생성 전용) 한다.
            self._prepare_crack(report)

            # 적대적 재검증(skeptic): 포착된 플래그를 '독립 재현' 관점에서 재채점해 확신도를
            # 보고에 싣고, 단일 출처면 독립 재읽기 명령을 수동 제안으로 남긴다(생성 전용 — 실행 아님).
            self._assess_flags(report)

            # [A6] LLM-심판(opt-in·advisory) — 증거가 '공략 달성'을 뒷받침하는지 별도 LLM 채점.
            # 규칙 판정(goal_reached·provenance)을 덮지 않고 조언만 싣는다(report.judge_verdict).
            self._run_judge(report, target)
        except KeyboardInterrupt:
            interrupted = True
            report.status = "interrupted"
            self.audit.event("interrupted", stage="post-loop")
        except Exception as e:   # noqa: BLE001 — 저장 보장 위해 흡수하되 감사에 남김(재개 상태 보존)
            self.audit.event("post_stage_error", error=f"{type(e).__name__}: {e}")
            post_stage_error = f"{type(e).__name__}: {e}"   # PHASE 4 상태를 'done' 으로 과장하지 않음

        # ── PHASE 4: REPORT ──
        report.status = "interrupted" if interrupted else "done"
        if post_stage_error and not interrupted:
            # 후처리(준비·평가) 스테이지에서 예외가 흡수됐으면 'done' 으로 묵인하지 않고 명시한다
            # (정직성 §3 — 일부 생성 전용 산출물이 누락됐을 수 있음). 코어 파이프라인·저장은 정상.
            report.message += (f"⚠ 후처리 단계 일부 오류({post_stage_error}) — 준비/평가 산출물 "
                               "일부 누락 가능(감사 로그 참조). 코어 결과·저장은 정상. ")
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
            if fd.get("verdict"):
                # 첫 실행에서 정한 출처 판정을 그대로 복원한다. 재계산하면 in_external
                # (라이트업·학습 유래)·오프라인 첨부 보정이 사라져, 정직성 표시가 조용히
                # 바뀌고(goal 상태가 뒤집혀) provenance 기능이 resume 에서 무력화된다(MED-2).
                prov = _prov.FlagProvenance(
                    kind, value, fd.get("prov_command", ""), fd.get("phase", ""),
                    fd["verdict"], fd.get("reason", ""))
            else:   # 구버전 상태(verdict 미저장) 호환 — 보수적 재계산
                prov = _prov.classify(kind, value, fd.get("source", ""))
            # [S4-2] 단일 경로(report.flags + flag_provenance + world.flags) 기록
            self._record_flag(report, FlagHit(value, kind, fd.get("source", "")), prov)
        # [S4] 자격증명 왕복 복원 — 과거엔 _persist 가 st.credentials 를 쓰기만 하고 _restore 가
        # 되읽지 않아, 재개 세션이 '수확한 자격증명'을 통째로 잃던 SSOT 결손(상태원 비대칭) 교정.
        # 볼트(재사용·{user}/{pass} 치환)와 월드(컨텍스트·prereq)를 startup 시드(294-296)와
        # 동일 형태로 함께 채운다 — add/add_cred 가 CLI·파일 자격증명과의 중복을 제거한다.
        if self.vault is not None and prior.credentials:
            self.vault.from_list(prior.credentials)
        if self.world is not None:
            for d in prior.credentials or []:
                user = (d or {}).get("username", "")
                if not user:
                    continue
                sec = d.get("password") or d.get("nt_hash") or ""
                self.world.add_cred(f"{user}:{sec}" if sec else user, d.get("source", ""))
        # [S5-3] 월드 식별 상태 복원 — 재개 시 raw_output(비영속)이 없어 핑거프린트가 '손실
        # 요약'으로 퇴행(S0 교정 무력화)하던 것을, 직전 실행에서 확정한 제품/버전으로 직접
        # 복원해 막는다. set_web_app 이 제품 고착·버전 보강 규칙을 그대로 적용.
        if self.world is not None and prior.web_product:
            self.world.set_web_app(prior.web_product, prior.web_version or "")
        # 수집물(loot) 복원 — 재개 시 world.loot 가 비면 _prereq_met("lateral") 의 bool(loot)
        # 전제가 met→unmet 으로 퇴행(1차 실행에선 돌던 lateral 이 재개 후 조용히 생략)했다.
        if self.world is not None:
            for item in prior.loot or []:
                self.world.add_loot(item, "재개 복원")
            # 학습 토픽(world.learned) 복원 — SSOT 완결·재개 후 동일 토픽 재학습 방지(LOW-1).
            for item in prior.learned or []:
                self.world.add_learned(item, "재개 복원")
            # 권한레벨 복원 — foothold 등에서 직접 올린 access_level(root 등)이 재개 시
            # 'none' 으로 퇴행하지 않게(privesc 재수행·goal 판정 왜곡 방지, LOW-2).
            if prior.access_level:
                self.world.raise_access(prior.access_level)
        # 자동 등록 vhost(이름→IP) 복원 — _maybe_register_vhost 가 채운 hosts_map/_vhost_seen 은
        # 비영속이라, 재개 시 vhost-only 웹앱이 out-of-scope 로 퇴행하던 결손(MED-1) 교정.
        if prior.hosts_map:
            if self.hosts_map is None:
                self.hosts_map = {}
            for host, ip in prior.hosts_map.items():
                if host not in self.hosts_map:
                    self.hosts_map[host] = ip
                self._vhost_seen.add(host)   # 1차 등록분은 재탐지·재등록하지 않음
        # 수집 해시 복원 — 재개 run 의 크래킹 준비가 직전 run 의 해시를 그대로 이어쓰게.
        for hv in prior.found_hashes or []:
            if hv not in self._found_hashes:
                self._found_hashes.append(hv)
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
    def _spent(findings: list[EnumFinding], base: int = 0,
               phase: str | None = None) -> int:
        """이번 실행에서 KB 열거 예산을 쓴 시도 수 — 도구 미설치(skipped)·예산 비계상
        (budgeted=False: 결정적 소비 스테이지 프로브)는 제외. [S5-1]

        [S5-1b] phase 를 주면 '그 단계에서만' 쓴 시도 수(단계별 공정배분). 과거엔 phase=None
        로 전역합산이라, 순서상 먼저 도는 enum 이 max_enum 을 독식하면 access/privesc/lateral
        의 KB 열거 예산이 0 으로 굶었다(boot2root 에서 privesc/lateral 열거가 핵심인데 치명적).
        이제 각 단계가 독립 예산 max_enum/max_llm 을 받는다(전역 cost_cap 은 여전히 상한)."""
        return sum(1 for f in findings[base:]
                   if not f.skipped and f.budgeted and (phase is None or f.phase == phase))

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
        # [S4-3(2)] 로직은 flag_assess.assess_flags 로 분리 — 얇은 위임(행위 보존).
        flag_assess.assess_flags(report)

    def _run_judge(self, report: OrchestrationReport, target: str) -> None:
        """[A6] LLM-심판(opt-in·advisory) — 증거(플래그·출처 판정·권한·상태·명령)만 보고 '공략
        달성' 주장이 뒷받침되는지 별도 LLM 채점. 규칙 판정을 덮지 않고 report.judge_verdict 에
        조언만 싣는다. --judge + LLM 라우터가 있을 때만(기본 비활성·비용 0). 실패는 조용히 생략."""
        if not self.judge or self.llm_router is None or self._cost_capped(report):
            return
        from . import judge as _judge
        flags = []
        prov = {(p.kind, p.value): p for p in report.flag_provenance}
        for f in report.flags:
            p = prov.get((f.kind, f.value))
            verdict = getattr(p, "verdict", "?") if p else "미분류"
            flags.append(f"{f.kind}={f.value} (출처판정: {verdict})")
        context = {
            "flags": flags,
            "access_level": self.world.access_level if self.world else "none",
            "state": self.world.context_lines() if self.world else [],
            "commands": [f.command for f in (report.enum_findings + report.llm_findings)
                         if f.ran][-8:],
        }
        try:
            raw = self.llm_router.judge(context, target)
            verdict = _judge.parse_judge(raw)
        except Exception as e:   # noqa: BLE001 — 심판 실패가 본 작업/보고를 막지 않음
            self.audit.event("judge_error", error=str(e))
            return
        if verdict is not None:
            report.judge_verdict = verdict
            self.audit.event("judge", score=verdict.score, passed=verdict.passed)

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
        """해커톤 시간 예산 마감 도달 여부(예산 0=무제한이면 항상 False).
        _deadline 은 run() 에서 설정되므로, run() 전(단위테스트 등 직접 호출)엔 getattr 로 안전.
        [T2-e] LLM 재시도/백오프 '대기' 시간은 예산에서 제외한다 — 일시 네트워크 블립의 대기가
        실제 작업 시간을 깎지 않도록 라우터가 보고한 slept 만큼 마감을 뒤로 민다(Deadline pause)."""
        deadline = getattr(self, "_deadline", None)
        if deadline is None:
            return False
        slept = float(getattr(self.llm_router, "slept_sec", 0.0) or 0.0)
        # [감사 F4] 마감 연장 상한 — 지속적 백오프가 시간 예산을 무한정 늘리지 못하게, slept 는
        # 최대 '예산 1회분'(time_budget 분)까지만 반영한다(총 실행 ≤ 2×예산).
        cap = float(getattr(self, "time_budget", 0) or 0) * 60.0
        if cap > 0 and slept > cap:
            slept = cap
        return self._clock() >= deadline + slept

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
        # detected_cve/cwe 는 영속하지 않는다 — 재개 시 _scan_vulns 가 복원된 finding 출력에서
        # 재도출하므로(_restore 는 읽지 않음), 저장본은 '쓰기 전용 死상태'였다(SSOT 오해 소지).
        if self.vault is not None and self.vault.creds:
            st.credentials = self.vault.to_list()
        # [S5-3] 월드 식별 상태·수집 해시 영속 — 재개 시 핑거프린트/크랙 준비가 퇴행하지 않게.
        if self.world is not None:
            if self.world.web_product:
                st.web_product = self.world.web_product
            if self.world.web_version:
                st.web_version = self.world.web_version
            if self.world.loot:
                st.loot = list(self.world.loot)   # 재개 시 lateral 전제(bool(loot)) 보존
            if self.world.learned:
                st.learned = list(self.world.learned)   # SSOT 학습 토픽 보존(재학습 방지)
            if self.world.access_level and self.world.access_level != "none":
                st.access_level = self.world.access_level   # 직접 상승분(root 등) 보존
        # 자동 등록 vhost(이름→IP) 영속 — 재개 시 스코프·_vhost_seen 복원(vhost-only 웹앱 보호)
        if self.hosts_map:
            st.hosts_map = dict(self.hosts_map)
        if getattr(self, "_found_hashes", None):
            st.found_hashes = list(self._found_hashes)
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
                if self._goal_reached(report) or self._time_up():   # 목표달성/시간소진 — 남은 후보 중단
                    break
                before = len(report.enum_findings)
                self._attempt(report, report.enum_findings, vcmd, phase)
                if len(report.enum_findings) > before:
                    # [감사 F5] 변형학습은 '원본 변형'(enum_findings[before])으로 기록한다.
                    # 출력구동 교정이 발화하면 뒤에 교정본이 append 돼 [-1] 이 교정본을 가리켜,
                    # base↔교정본 조합으로 fragment 통계가 오염됐다.
                    self._record_variant_outcome(base_cmd, report.enum_findings[before])
        else:
            # 병렬: 게이트(순차)→runner.run(동시)→처리(순차) 후 변형학습 기록
            gated = self._attempt_batch(report, report.enum_findings,
                                        [v for _, v in to_run], phase)
            for f in gated:
                self._record_variant_outcome(base_by_cmd.get(f.command, f.command), f)
        # [S5-4] '실제로 시도한' 명령 수만 진행도로 센다(slots = 도구 설치된 runnable 수).
        # 과거엔 len(to_run) 이라 도구 미설치(skipped) 후보도 진행으로 세어, 라운드 조기종료
        # (added==0) 를 한 라운드 늦추고 단계를 'skipped-only 인데 진행'으로 표시했다.
        return slots

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
            from .llm.base import Tier
            from .llm.tiering import tier_for
            # [lab:tiering] 같은 단계가 라운드를 거듭할수록(= 저렴 모델이 못 풀고 있을수록) 티어를
            # 한 단계씩 올린다. phase 기본값은 루트 tier_for_phase 그대로(privesc/lateral 은 STRONG).
            round_idx = self._phase_llm_rounds.get(phase, 0)
            base_tier = tier_for(phase, round_idx=round_idx)
            self._phase_llm_rounds[phase] = round_idx + 1
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
                    if self._goal_reached(report) or self._time_up():
                        break
                    self._attempt(report, report.llm_findings, c, phase)
            for (_c, m), f in zip(plain, report.llm_findings[n0:]):
                self._tag_llm_finding(report, f, m, focus)
        # 파일 액션: 순차 — 작성→실행→태깅(파일을 못 쓰면 그 파일을 쓰는 명령도 돌리지 않음)
        for cmd, m in files:
            if self._goal_reached(report) or self._time_up():
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
        # [lab:clues] 교차단계 '단서'(host/user/path/hash/software)를 도구 출력에서 누적해
        # LLM 후보 생성 컨텍스트로 되먹인다(Contextual Amnesia 완화 — 본 걸 잊지 않게).
        for f in (report.enum_findings + report.llm_findings):
            if f.output:
                self.clues.harvest(getattr(f, "raw_output", "") or f.output)
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
            "clues": self.clues.context_lines(),
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
        if res == "miss" and h.misses == report.plan.budget(h):
            # 임계는 가설별 가변 예산(budget(h))으로 — focus()/stuck() 과 일관. 고정 replan_after
            # 를 쓰면 저예산 가설은 focus 제외가 먼저 와 경고가 영영 안 뜨고, 고영향 가설은
            # stuck 전에 조기 경고가 떠 불일치가 생긴다(감사 F1).
            self.audit.event("hypothesis_stuck", hypothesis=hid, misses=h.misses)
            if not self.quiet:
                from . import ui
                print("  " + ui.mark_warn(f"{hid} 기대 신호 {h.misses}회 연속 불일치 — 분석가에게 재계획 요청"))
        return f"{hid} 신호 일치〔추정〕" if res == "hit" else f"{hid} 신호 불일치"

    def _discovery_targets(self) -> list[tuple[str, str]]:
        """제품→CVE 자동발견 대상 (제품, 버전) 목록 — 웹앱 + 관측 서비스에서 수집(중복 제거·상한).

        월드모델의 web_product/web_version(앱 계층 — 신종 CVE 가 몰리는 곳)과 서비스 배너의
        product/version 을 모아, 제품명 기준 중복을 제거하고 최대 4개로 제한한다(NVD 질의 폭주
        방지). 버전 없는 제품은 제외(과매칭 방지 — 버전 필터가 핵심)."""
        if self.world is None:
            return []
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        pairs: list[tuple[str, str]] = []
        if self.world.web_product:
            pairs.append((self.world.web_product, self.world.web_version or ""))
        for s in self.world.services:
            if getattr(s, "product", ""):
                pairs.append((s.product, getattr(s, "version", "") or ""))
        for prod, ver in pairs:
            key = prod.strip().lower()
            if not key or not ver.strip() or key in seen:
                continue   # 버전 없으면 건너뜀(버전 필터 없이는 과매칭) · 제품 중복 제거
            seen.add(key)
            out.append((prod.strip(), ver.strip()))
            if len(out) >= 4:
                break
        return out

    def _run_vuln(self, report: OrchestrationReport, host: NmapHost, target: str) -> None:
        """관측 코퍼스(배너·스크립트·enum/LLM 출력)에서 CVE/CWE·버전 매칭을 탐지해 리포트·월드에
        반영한다. 스윕 중 반복 호출되며(분석·명령 생성이 '확인 취약점'을 보도록) 결과는 누적·멱등."""
        # [최적화] 입력 코퍼스가 지난 호출과 같으면 재스캔 생략. _run_vuln 은 스윕당 6~10회+
        # 호출되며 매번 전 코퍼스를 join + 정규식 스캔(멱등). finding 의 output/raw_output 은
        # 생성 시점(_attempt)에 채워지므로 '개수' 키가 in-place 변이를 놓치지 않는다(새 결과=새 finding).
        fp = (len(report.enum_findings), len(report.llm_findings), len(host.ports))
        if getattr(self, "_vuln_fp", None) == fp:
            return
        self._vuln_fp = fp
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
    def _build_consume_scheduler(self, report: OrchestrationReport,
                                 host: NmapHost) -> "StageScheduler":
        """[S3] 결정적 소비 스테이지의 의존 선언형 스케줄러를 만든다(런당 1회).

        선언 순서 = 데이터 의존 DAG(생산자 → 소비자): 제품/버전 핑거프린트 → 버전 프로브 →
        익스 조회 → 웹 비밀. ``ready`` 는 전제(월드 상태), ``key`` 는 '소비하는' 상태의 서명이다.
        키가 바뀐(=입력이 자란) 스테이지만 재실행되고, 한 패스가 무실행이면 고정점에서 멈춘다.
        스케줄러의 ``_seen`` 은 스윕을 가로질러 유지돼 전역 멱등을 보장한다(기존 ``_*_probed``
        가드와 동일 의미를 명시적·테스트 가능한 1급 객체로 승격). 스테이지 본체는 불변."""
        from .scheduler import Stage, StageScheduler

        def _bases() -> list[str]:
            return self._web_bases(host)

        def _vhosts() -> tuple[str, ...]:
            tgt = self.world.target if self.world else ""
            return tuple(sorted(h for h, ip in (self.hosts_map or {}).items() if ip == tgt))

        def _opt_in() -> bool:
            return bool(self.exploit_exec or self.auto_poc)

        def _prod() -> str:
            return (self.world.web_product if self.world else "") or ""

        def _ver() -> str:
            return (self.world.web_version if self.world else "") or ""

        stages = [
            # 생산자: vhost 로 리다이렉트를 따라가 제품/버전을 결정적으로 식별(제품 미상일 때만).
            # 새 vhost/베이스가 관측되면(key 변화) 다시 시도. opt-in 전용.
            Stage(
                name="web_fingerprint",
                run=lambda: self._web_fingerprint_stage(report, host),
                ready=lambda: _opt_in() and not _prod() and bool(_bases()) and bool(_vhosts()),
                key=lambda: (len(self.hosts_map or {}), tuple(_bases())),
            ),
            # 소비자⓪: vhost 가 등록되면 그 '베이스 도메인'에 서브도메인(vhost) 브루트를 돌려
            # 'shared drive' 류 서브도메인 앱을 발견한다. 발견분은 _maybe_register_vhost 가 자동
            # 등록(출력의 *.htb 토큰) → 다음 스윕 열거. '발견' 단계라 enum 상한 밖(budgeted=False).
            Stage(
                name="vhost_brute",
                run=lambda: self._vhost_brute_stage(report, host),
                ready=lambda: _opt_in() and bool(_vhosts()),
                key=lambda: _vhosts(),
            ),
            # 소비자①: 제품은 잡혔으나 버전 미상이면 버전 노출 경로를 무해 GET(제품당 1회).
            Stage(
                name="version_probe",
                run=lambda: self._version_probe_stage(report, host),
                ready=lambda: bool(_prod()) and not _ver(),
                key=lambda: (_prod(),),
            ),
            # 소비자②: 제품에 맞는 공개 익스 조회(searchsploit). 제품이 바뀌면 재조회.
            Stage(
                name="exploit_lookup",
                run=lambda: self._exploit_lookup_stage(report, host),
                ready=lambda: bool(_prod()),
                key=lambda: (_prod(),),
            ),
            # 소비자③: 웹 노출 비밀/백업 열거(발판 전 자격 수확). 베이스·vhost·제품 중 하나가
            # 바뀌면 재열거. opt-in 전용.
            Stage(
                name="web_secret",
                run=lambda: self._web_secret_stage(report, host),
                ready=lambda: _opt_in() and bool(_bases()),
                key=lambda: (tuple(_bases()), _vhosts(), _prod()),
            ),
        ]
        return StageScheduler(stages)

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
                self._attempt(report, report.enum_findings, cmd, phase=phase, budgeted=False)
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
        if not bases:
            return
        if not vhosts:
            # vhost 미등록 — 요약/본문에 아직 vhost 가 안 떴어도, 루트가 '다른 호스트'로 302
            # 리다이렉트하는 (connected.htb·enigma.htb 류) 박스는 흔하다. 헤더 프로브(-sI)를 1회
            # 쏘면 그 출력이 _process → _maybe_register_vhost 를 거쳐 Location 헤더에서 vhost 를
            # 자동 등록한다(과거엔 여기서 return 해 vhost 리다이렉트 박스의 웹앱에 영영 못 닿았다).
            dkey = "vhost-discover|" + ",".join(sorted(bases))
            if dkey not in self._web_fp_probed:
                self._web_fp_probed.add(dkey)
                probe = f'curl -sI -k --max-time 10 {bases[0]}/'
                self._attempt(report, report.enum_findings, probe, phase=phase, budgeted=False)
                vhosts = [h for h, ip in (self.hosts_map or {}).items() if ip == tgt]
            if not vhosts:
                return                  # 리다이렉트 없음/외부 도메인 → 다음 스윕에
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
                # -L 는 --max-redirs 로 상한(대상 통제 리다이렉트 체인의 비스코프 egress 차단)
                cmd = f'curl -s -L --max-redirs 2 -k --max-time 10 -H "Host: {vh}" {bases[0]}/{p}'
                self._attempt(report, report.enum_findings, cmd, phase=phase, budgeted=False)
        # 새 관측을 즉시 반영 → 이번 스윕의 뒤 단계(web_secret·lookup)가 제품을 바로 활용.
        self._run_vuln(report, host, tgt)

    def _vhost_brute_stage(self, report: OrchestrationReport,
                           host: NmapHost | None = None, phase: str = "access") -> None:
        """등록된 vhost '베이스 도메인'에 서브도메인(vhost) 브루트를 돌려 숨은 앱(포털·shared
        drive 등)을 발견한다. 발견한 서브도메인은 출력의 *.htb 토큰을 _maybe_register_vhost 가
        자동 등록 → 다음 스윕에서 그 서브도메인 앱을 열거(완결 체인).

        핵심 설계:
          · **ffuf 자동 와일드카드 보정(-ac)** — HTB 는 '존재하지 않는 vhost 도 같은 랜딩'이 흔해
            보정 없이는 전부 거르거나 오탐한다. 무보정 gobuster vhost 가 실측(Enigma)에서 실패한 지점.
          · **타겟 IP 로 접속 + Host 헤더로 FUZZ.<도메인>** — /etc/hosts 해석에 의존하지 않고 동작
            (과거 KB 룰은 {t}→IP 치환으로 'FUZZ.<IP>' 라는 무의미한 브루트를 만들었다 — 그 버그 교정).
          · **enum 상한 밖(budgeted=False)** — '발견' 단계라 저가치 열거 폭에 밀려 미실행되면 안 된다
            (실측에서 vhost 브루트가 매번 '상한 초과 → 수동' 으로 잘려 실행 자체가 안 됐다).
        opt-in(--exploit-exec/--auto-poc) 전용·도메인당 1회·ffuf 미설치면 생략."""
        if host is None or self.world is None:
            return
        if not (self.exploit_exec or self.auto_poc):
            return
        if not self.is_tool_available("ffuf"):
            return
        import re as _re
        ip = str(self.guard.bound_target or self.world.target)
        # 베이스 도메인(X.htb — 점 1개)만. 이미 발견된 서브도메인(a.b.htb)은 재브루트하지 않는다.
        vhosts = [h for h, hip in (self.hosts_map or {}).items()
                  if hip == self.world.target and h.count(".") == 1 and _re.search(r"[a-z]", h)]
        wl = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        for vh in sorted(vhosts):
            if vh in self._vhost_brute_probed:
                continue
            self._vhost_brute_probed.add(vh)
            if self._goal_reached(report) or self._time_up():
                break
            cmd = (f'ffuf -w {wl} -u http://{ip}/ -H "Host: FUZZ.{vh}" -ac -t 50 -s')
            self._attempt(report, report.enum_findings, cmd, phase=phase, budgeted=False)

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
            self._attempt(report, report.enum_findings, cmd, phase=phase, budgeted=False)

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
            self._attempt(report, report.enum_findings, cmd, phase=phase, budgeted=False)
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

    # [6a] 실행 스테이지(_exploit_run_stage·_exploit_exec_stage·_foothold_stage·
    # _acquire_session)는 RCE/권한상승 '실행 표면'이라 foothold.FootholdMixin 으로 분리했다.
    # Orchestrator 가 그 믹스인을 상속하므로 런타임 동작은 완전히 동일(발사 로직 불변·행위 보존).
    # 상세: src/htb_agent/foothold.py 모듈 독스트링.

    # [S4-3] 준비 생성기 로직은 preparations 모듈의 자유 함수로 분리(god-object 축소).
    # 아래는 self 상태 → 명시 인자로 넘기는 얇은 위임 래퍼(행위 보존 — 생성 전용·실행 없음).
    def _prepare_revshells(self, report: OrchestrationReport) -> None:
        preparations.prepare_revshells(
            report, [str(ip) for ip in (self.guard.attacker_ips or [])],
            self.revshell_port, self.audit)

    def _prepare_cloud(self, report: OrchestrationReport) -> None:
        names: list[str] = []
        if self.hosts_map:
            names.extend(self.hosts_map.values())
            names.extend(self.hosts_map.keys())
        if self.guard.bound_host:
            names.append(str(self.guard.bound_host))
        names.append(report.target)
        preparations.prepare_cloud(report, names, self.audit)

    def _prepare_privesc(self, report: OrchestrationReport, prof: ProfileResult) -> None:
        attacker_ip = (str(list(self.guard.attacker_ips)[0])
                       if self.guard.attacker_ips else "")
        preparations.prepare_privesc(report, prof, attacker_ip, self.audit)

    def _consider_builtin_exploit(self, report: "OrchestrationReport", host) -> None:
        """핑거프린트된 제품/버전이 내장 익스 모듈과 매칭되면, 게이트-세이프하게 PoC 를 조달해
        실행 큐(poc_commands)에 투입하고 발판 캡처를 활성화한다(--exploit-exec/--auto-poc 옵트인).

        조달 순서(스코프 게이트 보존): ① 로컬 선조달분/이전 결과 → ② exploit-db(searchsploit -m,
        로컬 무해) 조달 후 재탐색. 외부 git 는 '자동 clone 하지 않고' 1회 수동 조달 안내만 남긴다
        (외부 호스트 접속을 게이트 우회로 자동화하지 않기 위함). 실제 PoC 실행은 _exploit_run_stage
        가 기존 3관문으로 수행한다. 매칭 모듈은 _active_exploit_module 로 걸어 발판 URL 캡처에 쓴다.
        인가/CTF 대상 전용(§4)."""
        if self.world is None or self.dry_run or not (self.exploit_exec and self.auto_poc):
            return
        if getattr(self, "_active_exploit_module", None) is not None:
            return   # 재진입 중복 금지(한 세션 1모듈)
        prod = (self.world.web_product or "").strip()
        ver = (self.world.web_version or "").strip()
        if not prod:
            return
        from . import exploit_modules
        mod = exploit_modules.match(prod, ver)
        if mod is None:
            # 탐지 결과 기반 자동 모듈화 — 내장/매니페스트에 없으면, '탐지된 CVE' 를 로컬
            # exploit-db(searchsploit --cve)로 해석해 런타임 모듈을 자동 등록한다(출처 비창작).
            mod = self._auto_module_from_cve(report, prod)
        if mod is None:
            return
        # 탐색 경로: 지정 poc_dir + 러너 작업디렉터리(shell/sandbox 러너는 searchsploit -m 조달물을
        # 자기 cwd=workspace.root 에 떨어뜨리므로 그걸 넣어야 직후 재탐색이 PoC 를 찾는다).
        extra = [self.poc_dir] if getattr(self, "poc_dir", "") else []
        rc_cwd = (getattr(self.runner, "workdir", None)
                  or getattr(getattr(self, "workspace", None), "root", None))
        if rc_cwd:
            extra.append(str(rc_cwd))
        poc_path = mod.find_local_poc(extra_dirs=extra)
        # exploit-db 에 있으면 로컬 무해 조달(searchsploit -m) 을 게이트로 실행 후 재탐색.
        if not poc_path and mod.edb_id:
            self._attempt(report, report.enum_findings, mod.fetch_command(), phase="access")
            poc_path = mod.find_local_poc(extra_dirs=extra)
        # 로컬에 없고 '옵트인(fetch_pocs)' 이면 레지스트리 선언 출처에서 자동 조달(git/searchsploit).
        # 받기만 하고(스코프 게이트와 독립한 도구 행위), 실행은 아래 _exploit_run_stage 가 3관문으로.
        if not poc_path and getattr(self, "fetch_pocs", False):
            from . import poc_fetch
            cache = self.poc_dir or poc_fetch.default_cache_dir()
            fetched = poc_fetch.fetch_module_poc(
                mod, cache, fetch_fn=getattr(self, "_poc_fetch_fn", None), audit=self.audit)
            if fetched:
                poc_path = fetched
                report.manual_suggestions.append(
                    f"# 공개 PoC 자동 조달됨 — {mod.cve}: {fetched} (출처: 레지스트리 선언. "
                    f"받은 제3자 공개 코드이며 실행은 3관문을 거침. 인가 대상 전용)")
        if not poc_path:
            hint = mod.manual_stage_hint()
            msg = (f"# 내장 익스 모듈 {mod.cve} 매칭({prod} {ver or '버전미상'}) — PoC 가 로컬에 "
                   f"없어 자동 발사 보류. 1회 받아 두면 이후 --full-auto 가 자동 사용(인가 대상 전용):")
            if hint:
                msg += "\n#   ↳ " + hint
            msg += (f"\n#   ↳ 받은 뒤 위치: 현재 디렉터리 · ~/.assassin/pocs/{mod.cve}/ "
                    f"또는 --poc-dir 로 지정")
            if msg not in report.manual_suggestions:
                report.manual_suggestions.append(msg)
            self.audit.event("builtin_exploit_poc_missing", cve=mod.cve, product=prod)
            return
        bases = self._web_bases(host) if host is not None else []
        scheme = "https" if any(b.startswith("https") for b in bases) else "http"
        lhost = (str(next(iter(self.guard.attacker_ips)))
                 if self.guard.attacker_ips else "")
        target = str(self.guard.bound_host or self.guard.bound_target or self.world.target)
        inv = mod.build_invocation(poc_path, target, scheme=scheme, lhost=lhost)
        if inv and inv not in self.poc_commands:
            self.poc_commands.append(inv)
        self._active_exploit_module = mod
        self.audit.event("builtin_exploit_queued", cve=mod.cve, product=prod, version=ver,
                         poc=poc_path, channel=mod.channel)
        report.manual_suggestions.append(
            f"# ⭐ 내장 익스 모듈 자동 발사 큐잉 — {mod.cve} ({mod.title}). PoC={poc_path} · "
            f"발판 채널={mod.channel}. 실행은 게이트·옵트인 하. 인가 대상 전용.")

    def _auto_module_from_cve(self, report: "OrchestrationReport", product: str):
        """탐지된 CVE(detected/discovered/vuln_matches)를 로컬 exploit-db(`searchsploit --cve`)로
        해석해 '런타임 익스 모듈'을 자동 등록한다(없으면 None). 출처는 로컬 exploit-db 뿐 — 임의/LLM
        URL 을 쓰지 않는다(공급망 안전). 등록된 모듈은 _consider_builtin_exploit 의 기존 조달·발사·
        캡처 체인을 그대로 탄다. '탐지→자동 추가→익스' 루프의 마지막 조각."""
        if not product:
            return None
        from . import exploit_modules
        cves: list[str] = []
        for c in (list(report.detected_cve) + list(getattr(report, "discovered_cve", []))):
            if c and c not in cves:
                cves.append(c)
        for m in report.vuln_matches:
            for c in getattr(m, "cve", []) or []:
                if c and c not in cves:
                    cves.append(c)
        lookup = getattr(self, "_cve_lookup_fn", None)
        for cve in cves[:6]:
            if not re.fullmatch(r"(?i)CVE-\d{4}-\d{4,7}", cve):
                continue
            try:
                out = (lookup(cve) if lookup is not None
                       else self._safe_run(f"searchsploit --cve {cve}").stdout)
            except Exception as e:   # noqa: BLE001 — 조회 실패가 전체를 깨지 않도록
                self.audit.event("auto_module_lookup_error", cve=cve, error=str(e))
                continue
            mod = exploit_modules.module_for_cve(cve, product, out or "")
            if mod is not None:
                # 전역 레지스트리(_RUNTIME)에 등록하지 않는다 — 이 모듈은 '이 세션의 이 탐지' 전용이다.
                # 전역에 넣으면 단일 프로세스 다중 타겟(livebench 배치)에서 다른 타겟으로 누수·오염된다.
                # _consider_builtin_exploit 는 반환된 mod 를 직접 쓰고 self._active_exploit_module 로만
                # 건다(전역 조회 불필요). 사용자 지정 모듈(load_manifest)만 전역에 영속한다.
                self.audit.event("auto_module_from_cve", cve=cve, edb=mod.edb_id, product=product)
                report.manual_suggestions.append(
                    f"# 탐지 CVE {cve} → exploit-db PoC 자동 모듈 등록(EDB-{mod.edb_id}, "
                    f"{mod.title}). 로컬 DB 출처 · 게이트·옵트인 하 발사. 인가 대상 전용.")
                return mod
        return None

    def _prepare_lateral(self, report: OrchestrationReport) -> None:
        """수확한 크리덴셜/NT 해시를 '열린 다른 서비스' 재사용·PtH 후보로 준비(생성 전용)."""
        creds: list[tuple[str, str]] = []
        nt_hashes: list[tuple[str, str]] = []
        if self.world is not None:
            for c in self.world.creds:
                if ":" not in c:
                    continue
                user, secret = c.split(":", 1)
                user = user.strip()
                secret = secret.strip().strip("<>").strip()   # 'user:<HASH>'·'user:HASH' 모두
                if not user or not secret:
                    continue
                # NT 해시(정확히 32 hex)는 PtH 후보로만 — 평문 비밀번호와 혼동 금지(감사 B-MED1).
                # 과거엔 parse_cred 가 'user:HASH'(꺾쇠 없음)를 평문으로 받아 해시를 -p 로도
                # 스프레이하는 가짜 후보를 만들었다. 해시 모양이면 nt_hashes 로만 보낸다.
                if re.fullmatch(r"[0-9a-fA-F]{32}", secret):
                    pair = (user, secret)
                    if pair not in nt_hashes:
                        nt_hashes.append(pair)
                else:
                    pc = (user, secret)
                    if pc not in creds:
                        creds.append(pc)
        if self.vault is not None:
            for cred in self.vault.creds:
                nt = getattr(cred, "nt_hash", None)
                user = getattr(cred, "username", "") or ""
                if nt and user:
                    nt = nt.split(":")[-1]   # 'LM:NT' 면 NT 부분만
                    pair = (user, nt)
                    if pair not in nt_hashes:
                        nt_hashes.append(pair)
        target = str(self.guard.bound_target or self.guard.bound_host or report.target or "")
        preparations.prepare_lateral(report, target, creds, nt_hashes, self.audit)

    # [S5-4] 사장 메서드 _privesc_analyze_stage 제거 — 호출부 없음. privesc 벡터 분석은
    # preparations.prepare_privesc 안에서 preparations.privesc_analyze 로 직접 수행된다.

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
        # [S4-3] 로직은 preparations.prepare_crack 으로 분리 — 얇은 위임(행위 보존).
        preparations.prepare_crack(
            report, list(getattr(self, "_found_hashes", [])), self.vault, self.audit)

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
              cmd: str, phase: str, budgeted: bool = True) -> EnumFinding | None:
        """3관문(도구·검증·범위·승인)을 순차 수행(공유상태 변경은 단일 스레드).
        통과하면 '실행 대상' finding 반환, 아니면 사유를 기록하고 None.
        budgeted=False 면 이 finding 은 KB 열거 예산(max_enum)에 계상하지 않는다([S5-1])."""
        finding = EnumFinding(command=cmd, phase=phase, budgeted=budgeted)
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

    def _process(self, report: OrchestrationReport, finding: EnumFinding, out,
                 corrective: bool = False) -> None:
        """실행 결과를 반영(파싱·플래그/해시/크리덴셜 스캔). 공유상태를 변경하므로
        반드시 단일 스레드에서, 제출 순서대로 호출한다(병렬 실행과 분리).
        corrective=True 면 이 finding 은 교정 재시도분이라 추가 교정을 걸지 않는다(재귀 방지)."""
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
            if hit.value in {f.value for f in report.flags}:
                continue
            # 출처 검증(실행 트레이스 기반) — 이 플래그를 만든 명령을 분류해 기록.
            prov = self._classify_flag(report, hit, cmd, finding.phase)
            self._record_flag(report, hit, prov)   # [S4-2] 단일 경로(report+world) 기록
            note_mark = f"🚩 {hit.kind} flag"
            if prov.verdict != "exploit-derived":
                note_mark += f"({prov.label})"
            finding.note = (finding.note + " " if finding.note else "") + note_mark
            self.audit.event("flag_found", kind=hit.kind, value=hit.value, cmd=cmd,
                             provenance=prov.verdict)
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
        # vhost 발견은 '요약'이 아니라 '원본'에서 — 요약기(summarize_tool_output)가 ffuf/헤더
        # 출력의 서브도메인·Location 줄을 트렁케이트로 날릴 수 있다(발판 URL 캡처와 동일 원칙).
        self._maybe_register_vhost(report, getattr(finding, "raw_output", "") or finding.output)
        # [T1-a] 출력구동 Results Verifier — 실행 후 출력을 보고 '한 끗 빠진' 명령을 교정해
        # 1회 재시도(생성 전용 — 교정본도 3관문 재통과). 교정분은 corrective=True 라 재귀 안 함.
        if not corrective:
            self._maybe_corrective_retry(report, finding, out)

    def _maybe_corrective_retry(self, report: OrchestrationReport,
                                finding: EnumFinding, out) -> None:
        """실행 결과가 교정 가능한 실패면(results_verify 규칙) 교정본을 3관문에 1회 재투입.
        유한·예산보호: 원 명령당 1회, 전역 상한(_verify_budget_left), 시간 소진 시 생략,
        교정본은 KB 열거 예산에 계상하지 않음(budgeted=False)."""
        if self.dry_run or self._time_up():
            return
        if not hasattr(self, "_verify_retried"):   # run() 미경유(직접 호출/테스트) 안전 초기화
            self._verify_retried = set()
            self._verify_budget_left = 8
        if self._verify_budget_left <= 0 or finding.command in self._verify_retried:
            return
        corr = results_verify.corrective_command(finding.command, out)
        if corr is None:
            return
        new_cmd, reason = corr
        self._verify_retried.add(finding.command)
        # 교정본이 이미 시도됐거나(중복) 원본과 같으면 건너뜀
        done = {f.command for f in (report.enum_findings + report.llm_findings)}
        if new_cmd == finding.command or new_cmd in done:
            return
        self._verify_budget_left -= 1
        finding.note = (finding.note + " · " if finding.note else "") + f"✎ 출력구동 교정({reason})"
        self.audit.event("results_verify", original=finding.command, fixed=new_cmd, reason=reason)
        self._attempt(report, report.enum_findings, new_cmd, finding.phase,
                      budgeted=False, corrective=True)

    def _analyze_offline_files(self, report: OrchestrationReport) -> None:
        """[G2] 첨부 바이너리마다 export-first 정적 분석 명령을 3관문에 투입(생성 전용·비실행).
        바이너리를 '실행'하지 않는 정적 도구만(file/strings/nm/objdump/checksec/r2 -A). 예산
        비계상(budgeted=False) — 열거 예산을 쓰지 않는 결정적 분석 패스."""
        ws = self.workspace
        if ws is None or not getattr(ws, "imported", None):
            return
        import os as _os
        # 재개 복원분(이미 투입된 export-first 명령)도 skip 집합에 포함 — 재개 시 file/strings/nm
        # 중복 재실행 방지(감사 F2). _gate/_attempt 는 seen_cmds 를 보지 않으므로 여기서 거른다.
        seen: set[str] = {f.command for f in report.enum_findings}
        for rel in list(ws.imported)[:10]:   # 파일 수 상한(과다 첨부 방어)
            full = _os.path.join(ws.root, rel)
            for cmd in reversing.export_first_commands(full):
                if cmd in seen:
                    continue
                seen.add(cmd)
                self._attempt(report, report.enum_findings, cmd, phase="access",
                              budgeted=False, corrective=True)   # corrective=재귀 교정 억제

    def _maybe_register_vhost(self, report: OrchestrationReport, text: str) -> None:
        """리다이렉트 출력에서 vhost 를 발견하면 타겟 IP 로 스코프 해석맵(hosts_map)에
        자동 등록한다 → 프롬프트·스킵 없이 진행. OS 이름해석(/etc/hosts)은 권한 있으면
        자동 추가, 없으면 '조용한 반복 실패' 대신 1회 또렷한 안내를 남긴다.
        스코프는 '타겟 IP' 로만 묶으므로 범위를 넓히지 않는다(안전).

        ⚠️ 신뢰 경계: 리다이렉트 Location 은 '대상이 통제하는' 값이다. 임의 외부 도메인
        (evid.com·CDN·SSO 등)을 등록하면 scope_guard 가 그 호스트를 TARGET 으로 오분류해
        비스코프 egress 를 auto-allow 하게 된다(대상 출력이 스코프를 넓히는 우회). 그래서
        HTB 랩 vhost 관례(.htb/.local — scope_guard 의 특수취급과 동일)로만 자동 등록하고,
        그 밖의 외부 도메인은 '등록하지 않고' 1회 수동 안내만 남긴다."""
        if not text or self.guard.bound_target is None:
            return
        if not hasattr(self, "_vhost_seen"):
            self._vhost_seen = set()   # run() 밖(스테이지 직접 호출)에서도 안전
        ip = str(self.guard.bound_target)
        # 후보 수집: ① 요약 화살표(→ http://host) ② raw Location 헤더(웹 프로브 -i/-I 출력)
        # ③ 본문/PDF/배너에 박힌 bare *.htb/*.local 토큰. ②가 핵심 — 과거엔 화살표 요약 형식만
        # 봐서, curl 이 내는 '진짜 302 Location' 으로는 vhost 를 못 잡았다(웹 리다이렉트 박스 미해금).
        # ③은 .htb/.local 만 받아(scope_guard 랩 vhost 특수취급과 동일) 외부 도메인 노이즈를 배제.
        cands: list[str] = []
        for rx in (_REDIRECT_HOST_RE, _LOCATION_HOST_RE, _HTB_VHOST_RE):
            for m in rx.finditer(text):
                h = m.group(1).lower().rstrip(".")
                if h and h not in cands:
                    cands.append(h)
        for host in cands:
            if (not host or host in self._vhost_seen or not re.search(r"[a-z]", host)
                    or (self.hosts_map or {}).get(host)):
                continue
            # HTB 랩 vhost(.htb/.local)만 타겟 IP 로 자동 등록. 외부 도메인은 대상이 통제하는
            # 리다이렉트로 스코프를 넓히지 못하도록 등록 거부 + 1회 안내(우회 차단).
            if not (host.endswith(".htb") or host.endswith(".local")):
                self._vhost_seen.add(host)   # 반복 안내 억제
                self.audit.event("vhost_external_skipped", host=host)
                report.manual_suggestions.append(
                    f"# 리다이렉트가 외부 도메인 {host} 를 가리킴 — 스코프 자동확장 안 함"
                    f"(대상 통제값). 권한 확인 자산이면 수동으로 범위·해석 추가 후 진행.")
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
                self.audit.event("etc_hosts_added", host=host, ip=ip, via="direct")
                return
        except OSError:
            pass
        # [env-auto] 쓰기 권한 없음(비root 실행) → '--priv-env' 명시 옵트인일 때만 sudo -n(비대화형)
        # 로 자동 추가(권한 작업은 전용 플래그 뒤로). 기본은 Host 헤더 기반 hosts_map 으로 이미
        # 웹 경로가 동작하므로, sudo 없이도 핵심 자동화는 유지된다. 실패 시 1회 수동 안내.
        if getattr(self, "priv_env", False) and hosts_path == "/etc/hosts":
            sudo_fn = getattr(self, "_hosts_sudo_fn", None)
            try:
                if sudo_fn is not None:
                    rc = sudo_fn(line)
                else:
                    import subprocess
                    p = subprocess.run(["sudo", "-n", "tee", "-a", hosts_path],
                                       input=line + "\n", capture_output=True, text=True,
                                       timeout=15)
                    rc = p.returncode
                if rc == 0:
                    self.audit.event("etc_hosts_added", host=host, ip=ip, via="sudo")
                    return
            except (OSError, ValueError):
                pass
        hint = (f"이름해석 1회 설정(그러면 {host} 명령이 완전 자동 진행): "
                f"echo '{line}' | sudo tee -a /etc/hosts")
        if hint not in report.manual_suggestions:
            report.manual_suggestions.append(hint)

    def _nfs_harvest_stage(self, report: OrchestrationReport, host) -> None:
        """[env-auto] 열린 NFS export 를 읽어 자격·SSH 키·플래그를 수확한다(옵트인·타겟 IP 한정).

        안전·자동화 우선순위:
          (1) **rootless 기본**: libnfs(`nfs-ls`/`nfs-cp`)로 **sudo·마운트 없이** 읽는다 — root 도
              시스템 변경도 없어 --full-auto 만으로 완전 자동이면서 가장 안전하다.
          (2) libnfs 미설치 + **`--priv-env` 명시 옵트인** 일 때만 `sudo -n` ro 마운트→스캔→umount
              로 폴백(권한 작업은 전용 플래그 뒤로 — 기본 --full-auto 는 root 작업 안 함).
          (3) 둘 다 불가면 1회 수동 안내(무확인 강제 아님).
        수확한 자격/키/사용자는 world·후속 SSH 키 로그인으로 이어진다. 원격·마운트 트리에서 아무
        것도 '실행'하지 않는다(정적 읽기 only). 인가 대상 전용."""
        if self.world is None or self.dry_run or not (self.exploit_exec or self.auto_poc):
            return
        if host is not None and host.open_ports and not ({111, 2049} & set(host.open_ports)):
            return   # NFS 신호(111/2049) 없으면 생략
        import os
        import shutil
        import tempfile

        from . import nfs_recon
        from . import provenance as _prov
        from .flag import FlagHit
        ip = str(self.guard.bound_target or self.world.target)
        exports: list[str] = []
        for f in report.enum_findings:
            if "showmount" in (f.command or ""):
                exports = nfs_recon.parse_exports(getattr(f, "raw_output", "") or f.output or "")
                if exports:
                    break
        if not exports:
            out = self._safe_run(f"showmount -e {ip}", 30)
            exports = nfs_recon.parse_exports(getattr(out, "stdout", "") or "")
        if not exports:
            return
        if getattr(self, "_nfs_keystore", None) is None:
            self._nfs_keystore = tempfile.mkdtemp(prefix="assassin_nfskeys_")
        run_fn = getattr(self, "_nfs_run_fn", None) or nfs_recon._run
        rootless = getattr(self, "_nfs_force_libnfs", None)
        if rootless is None:
            rootless = self.is_tool_available("nfs-ls")
        harvested_keys: list[str] = []
        harvested_users: list[str] = []

        def _reflect(fnd, export):   # 공통: 수확 결과를 world/플래그/안내로 반영
            for u, p in fnd.creds:
                self.world.add_cred(f"{u}:{p}", source=f"NFS {export}")
            for u in fnd.users:
                if u not in harvested_users:
                    harvested_users.append(u)
            for kind, val in fnd.flags:
                prov = _prov.FlagProvenance(kind, val, f"<NFS {export}>", "access",
                                            "exploit-derived", f"NFS export {export} 에서 직접 읽음")
                self._record_flag(report, FlagHit(val, kind, "NFS"), prov)
            for k in fnd.ssh_keys:
                if k not in harvested_keys:
                    harvested_keys.append(k)
            if fnd.creds or fnd.ssh_keys or fnd.flags:
                self.audit.event("nfs_harvest", export=export, via=("libnfs" if rootless else "mount"),
                                 creds=len(fnd.creds), keys=len(fnd.ssh_keys), flags=len(fnd.flags))
                report.manual_suggestions.append(
                    f"# NFS export {export} 수확 — 자격 {len(fnd.creds)} · SSH키 {len(fnd.ssh_keys)} · "
                    f"플래그 {len(fnd.flags)} · 주목 파일: {', '.join(fnd.notable[:6]) or '없음'}")

        for export in exports[:5]:
            # (1) rootless(libnfs) 우선 — sudo·마운트 없음
            if rootless:
                fnd, ok = nfs_recon.scan_via_libnfs(ip, export, run_fn, self._nfs_keystore,
                                                    flag_kind=self.flag_kind)
                if ok:
                    self.audit.event("nfs_read", export=export, via="libnfs")
                    _reflect(fnd, export)
                    continue
                # libnfs 목록 실패 → 아래 폴백으로
            # (2) sudo 마운트 폴백 — '--priv-env' 명시 옵트인일 때만(권한 작업 전용 플래그)
            if getattr(self, "priv_env", False):
                mounter = getattr(self, "_nfs_mount_fn", None) or nfs_recon.sudo_mount
                umounter = getattr(self, "_nfs_umount_fn", None) or nfs_recon.sudo_umount
                mp = tempfile.mkdtemp(prefix="assassin_nfs_")
                ok, err = False, ""
                for vers in ("3", "4"):
                    try:
                        ok, err = mounter(ip, export, mp, vers=vers)
                    except TypeError:
                        ok, err = mounter(ip, export, mp)
                    if ok:
                        break
                if not ok:
                    self.audit.event("nfs_mount_failed", export=export, error=str(err)[:200])
                    hint = nfs_recon.manual_hint(ip, export)
                    if hint not in report.manual_suggestions:
                        report.manual_suggestions.append(hint)
                    try:
                        os.rmdir(mp)
                    except OSError:
                        pass
                    continue
                self.audit.event("nfs_mounted", export=export, mountpoint=mp)
                try:
                    fnd = nfs_recon.scan_tree(mp, export=export, flag_kind=self.flag_kind)
                    persisted: list[str] = []
                    for k in fnd.ssh_keys:   # umount 전 0600 보존 복사(키 경로는 마운트 내부)
                        dest = os.path.join(self._nfs_keystore, f"key_m{len(harvested_keys) + len(persisted)}")
                        try:
                            shutil.copyfile(k, dest)
                            os.chmod(dest, 0o600)
                            persisted.append(dest)
                        except OSError:
                            pass
                    fnd.ssh_keys = persisted
                finally:
                    umounter(mp)
                    try:
                        os.rmdir(mp)
                    except OSError:
                        pass
                _reflect(fnd, export)
                continue
            # (3) rootless 불가 + --priv-env 아님 → 수동 안내(설치 또는 전용 플래그)
            hint = ("NFS export 자동 수확 보류 — rootless 도구 설치 권장(완전 자동): "
                    "sudo apt install -y libnfs-utils  (또는 sudo 마운트 허용: --priv-env). "
                    f"수동: {nfs_recon.manual_hint(ip, export)}")
            if hint not in report.manual_suggestions:
                report.manual_suggestions.append(hint)
            self.audit.event("nfs_skip", export=export, reason="no_libnfs_no_privenv")
        # 수확한 SSH 키로 로그인해 플래그 읽기(타겟 22 열림 시·opt-in)
        if harvested_keys and (host is None or not host.open_ports or 22 in host.open_ports):
            self._try_ssh_keys(report, harvested_keys, harvested_users)

    def _try_ssh_keys(self, report: OrchestrationReport, keys: list, users: list) -> None:
        """수확한 SSH 개인키로 타겟(22)에 로그인해 플래그를 읽는다. 사용자 후보는 수확분 + 흔한
        기본값. 키 인증이라 sshpass 불필요. 각 (키,유저) 1회·상한 8회, 3관문(_attempt) 하 실행."""
        import os
        import shlex
        if not self.is_tool_available("ssh"):
            report.manual_suggestions.append(
                "# SSH 키 수확됨 — 'ssh -i <키> <user>@<타겟>' 으로 로그인·플래그 읽기 권장(ssh 미설치)")
            return
        import re as _re

        from . import provenance as _prov
        from .flag import FlagHit, extract_flags
        target = str(self.guard.bound_host or self.guard.bound_target or self.world.target)
        cand: list[str] = []
        for u in [*users, "root", "admin"]:
            if u and u not in cand:
                cand.append(u)
        tries = 0
        for key in keys[:3]:
            for user in cand[:5]:
                if tries >= 8 or self._goal_reached(report) or self._time_up():
                    return
                tries += 1
                # user.txt/root.txt 를 '라벨'로 분리 출력 → 종류(user/root)를 명확히 기록(혼동 방지).
                cmd = (f"ssh -i {shlex.quote(key)} -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                       f"-o PreferredAuthentications=publickey -o PasswordAuthentication=no "
                       f"-o BatchMode=yes {shlex.quote(user)}@{target} "
                       f"'id; echo USERTXT:$(cat ~/user.txt 2>/dev/null || cat /home/*/user.txt 2>/dev/null); "
                       f"echo ROOTTXT:$(cat /root/root.txt 2>/dev/null)'")
                before = len(report.enum_findings)
                self._attempt(report, report.enum_findings, cmd, phase="access")
                if len(report.enum_findings) <= before:
                    continue
                raw = (getattr(report.enum_findings[before], "raw_output", "")
                       or report.enum_findings[before].output or "")
                if "uid=" not in raw:
                    continue
                self.world.add_cred(f"{user}:<ssh-key:{os.path.basename(key)}>", source="NFS SSH키")
                self.audit.event("nfs_ssh_key_login", user=user, key=os.path.basename(key))
                for kind, label in (("user", "USERTXT:"), ("root", "ROOTTXT:")):
                    m = _re.search(rf"{label}(.*)", raw)
                    if not m:
                        continue
                    for val in extract_flags(m.group(1)):
                        prov = _prov.FlagProvenance(kind, val, "<SSH 키 로그인 직독>", "access",
                                                    "exploit-derived", f"{user} SSH 키 로그인 후 직접 읽음")
                        self._record_flag(report, FlagHit(val, kind, "SSH키"), prov)
                return   # 로그인 성공 — 더 시도하지 않음

    def _mail_domain(self) -> str:
        """메일 user@domain 형식용 베이스 도메인 추정 — 자동등록 vhost/hosts_map 에서.
        'mail001.enigma.htb' 같은 3+라벨은 마지막 2라벨('enigma.htb')을 베이스로 본다."""
        names = list(getattr(self, "_vhost_seen", None) or []) + list((self.hosts_map or {}).keys())
        for n in names:
            parts = (n or "").strip().split(".")
            if len(parts) >= 2 and all(parts):
                return ".".join(parts[-2:])
        return ""

    def _mail_harvest_stage(self, report: OrchestrationReport, host) -> None:
        """수확한 평문 자격을 메일(IMAP/POP3)에 로그인해 본문에서 '다음 자격·플래그'를 수확한다.
        실측(Enigma): 온보딩 PDF 자격이 webmail 계정이라 SSH 분사만으로는 발판이 안 섰다 —
        메일 본문의 다음 자격을 world.creds 로 되먹여 이후 SSH 발판이 쓰게 한다.
        옵트인(exploit_exec/auto_poc)·타겟 IP 한정·읽기 전용(전송 없음)."""
        if self.world is None or self.dry_run or not (self.exploit_exec or self.auto_poc):
            return
        from . import mail_recon
        from . import provenance as _prov
        from .flag import FlagHit
        from .target_shell import parse_cred
        open_ports = list(host.open_ports) if (host is not None and host.open_ports) else None
        if open_ports is not None and not mail_recon.has_mail_port(open_ports):
            return   # 메일 포트(110/143/993/995) 신호 없으면 생략
        import re
        creds: list[tuple[str, str]] = []
        for c in self.world.creds:
            pc = parse_cred(c)
            if not pc or pc in creds:
                continue
            if re.fullmatch(r"[0-9a-fA-F]{32}", pc[1]):   # NT 해시는 평문 로그인 아님
                continue
            creds.append(pc)
        if not creds:
            self.audit.event("mail_harvest_skip", reason="no_plaintext_cred")
            return
        ip = str(self.guard.bound_target or self.world.target)
        imap_fn = getattr(self, "_mail_imap_fn", None) or mail_recon.imap_fetch
        pop3_fn = getattr(self, "_mail_pop3_fn", None) or mail_recon.pop3_fetch
        findings = mail_recon.try_mail_logins(
            ip, creds, open_ports=open_ports, domain=self._mail_domain(),
            fetch_imap=imap_fn, fetch_pop3=pop3_fn, flag_kind=self.flag_kind)
        new_creds = 0
        for fnd in findings:
            self.audit.event("mail_login", endpoint=fnd.endpoint, msgs=fnd.msg_count,
                             creds=len(fnd.creds), flags=len(fnd.flags))
            for u, p in fnd.creds:
                before = len(self.world.creds)
                self.world.add_cred(f"{u}:{p}", source=f"메일 {fnd.endpoint}")
                new_creds += len(self.world.creds) - before
            for kind, val in fnd.flags:
                prov = _prov.FlagProvenance(kind, val, f"<메일 {fnd.endpoint}>", "access",
                                            "exploit-derived", "메일 본문에서 직접 읽음")
                self._record_flag(report, FlagHit(val, kind, "메일"), prov)
            if fnd.creds or fnd.flags:
                report.manual_suggestions.append(
                    f"# 메일 로그인 {fnd.endpoint} — 본문에서 자격 {len(fnd.creds)} · "
                    f"플래그 {len(fnd.flags)} 수확 (제목: {', '.join(fnd.notable[:3]) or '—'})")
        if findings and new_creds:
            self.audit.event("mail_harvest", logins=len(findings), new_creds=new_creds)

    def _classify_flag(self, report: OrchestrationReport, hit, cmd: str, phase: str):
        # [S4-3(2)] 로직은 flag_assess.classify_flag 로 분리 — self.workspace/self.kb 를
        # 명시 인자로 넘기는 얇은 위임(행위 보존 — 분류·판정 전용).
        return flag_assess.classify_flag(report, hit, cmd, phase, self.workspace, self.kb)

    def _record_flag(self, report: OrchestrationReport, hit, prov=None) -> bool:
        """[S4-2] 플래그를 상태원에 '단일 경로'로 기록한다 — report.flags(+flag_provenance)와
        world.flags 를 한 번에 갱신. 중복(값 기준)이면 아무것도 안 하고 False.

        과거엔 포착(_process)·재개(_restore)·발판(_foothold_stage)이 제각기
        report.flags.append + world.add_flag 를 따로 호출했고, 발판 경로는 world.add_flag
        '만' 불러 flag_read 로 얻은 플래그가 report.flags 에 안 잡혔다(→ user/root_flag·
        goal_reached 가 못 봄). 이 단일 경로로 모아 그 상태원 분기를 구조적으로 차단한다.
        prov 가 있으면 함께 기록(없으면 provenance 미부여). 실행/발사 로직과 무관 — 상태 반영만.

        [S5-2] 정직성 가드: world(권한레벨·신뢰 상태)에는 **공략 유래(exploit-derived) 플래그만**
        반영한다. 과거엔 모든 스캔 플래그를 world.add_flag → raise_access 로 무조건 올려, 로컬
        출력의 미끼/예시/라이트업 유래 플래그가 world.access_level 을 user/root 로 올리고
        _prereq_met 를 충족시켜(투기적 LLM 라운드 오발) context/fingerprint 를 오염시켰다.
        report.flags 는 '관측된 모든 플래그'를 담고, world 는 '신뢰되는 상태'만 담는다(goal_reached
        와 동일 기준 verdict=="exploit-derived"). report 는 전부 기록하므로 사람에겐 다 보인다.
        """
        # 중복 판정은 (종류, 값) 기준 — 과거엔 값만 봐, user/root 플래그가 우연히 같은 값이면
        # 둘째 종류가 report·world 양쪽에서 누락돼 goal_reached(user+root 필요)가 영영 불충족될 수
        # 있었다(실무상 user.txt≠root.txt라 희박하나 dedup 키는 (kind,value)가 옳다).
        if (hit.kind, hit.value) in {(f.kind, f.value) for f in report.flags}:
            return False
        report.flags.append(hit)
        if prov is not None:
            report.flag_provenance.append(prov)
        # world(신뢰 상태)에는 공략 유래 플래그만 — 미신뢰 플래그로 권한레벨이 오염되지 않게.
        if self.world is not None and prov is not None and prov.verdict == "exploit-derived":
            # [A5] 플래그 리니지에 출처 명령을 실어 둔다(유래 추적·writeup 설명).
            self.world.add_flag(hit.kind, hit.value, source=getattr(prov, "command", "") or "")
        return True

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

    def _safe_run(self, cmd: str, timeout: int = 180) -> "RunOutput":
        """runner.run 을 예외로부터 보호. 어떤 러너 예외도 실패 RunOutput 으로 흡수해
        한 명령의 실패가 라운드/배치 전체를 깨지 않도록 한다(병렬 map 보호 포함).
        timeout 은 러너 실행 상한(초) — 폴링형 PoC 는 모듈이 더 긴 값을 요구할 수 있다."""
        try:
            return self.runner.run(cmd, timeout=max(1, int(timeout)))
        except Exception as e:   # noqa: BLE001
            self.audit.event("run_exception", cmd=cmd, error=f"{type(e).__name__}: {e}")
            return RunOutput(cmd, error=f"러너 예외: {type(e).__name__}: {e}", returncode=-1)

    def _attempt(self, report: OrchestrationReport, findings: list[EnumFinding],
                 cmd: str, phase: str = "enum", budgeted: bool = True,
                 corrective: bool = False, timeout: "int | None" = None) -> None:
        """순차 실행: 게이트 → (통과 시) 실행 → 결과 처리.
        budgeted=False 면 KB 열거 예산(max_enum)에 계상하지 않는다([S5-1] 소비 스테이지용).
        corrective=True 면 이 finding 은 '출력구동 교정 재시도'라 또 교정하지 않는다(재귀 방지).
        timeout 이 주어지면 러너 실행 상한을 그 값으로 올린다(폴링형 PoC 전용 — None 이면 기본 180s)."""
        finding = self._gate(report, findings, cmd, phase, budgeted=budgeted)
        if finding is None:
            return
        if self.dry_run:   # 계획 미리보기 — 게이트까지 통과했으나 실행하지 않음
            finding.note = (finding.note + " · " if finding.note else "") + "dry-run: 제안만(미실행)"
            report.gate_stats["dry_run"] = report.gate_stats.get("dry_run", 0) + 1
            return
        out = self._safe_run(finding.command, 180 if timeout is None else timeout)
        self._process(report, finding, out, corrective=corrective)

    def _attempt_batch(self, report: OrchestrationReport, findings: list[EnumFinding],
                       cmds: list[str], phase: str) -> list[EnumFinding]:
        """병렬 실행: 게이트를 '순차로' 통과시킨 뒤, 통과한 명령의 runner.run 만
        스레드풀로 동시 실행하고, 결과 처리는 다시 '제출 순서대로 단일 스레드'로
        수행한다 → 공유상태 경쟁 없음·결정적 순서 보존. 게이트 통과 finding 목록 반환."""
        if self._time_up():   # 시간 예산 소진 — 배치를 띄우지 않음(스레드는 중간 중단 불가)
            return []
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
