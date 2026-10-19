"""
HTB 에이전트 CLI 진입점 (Kali 런타임)
======================================

사용 예:
  python3 -m htb_agent.main 10.129.1.5                  # 승인제 포트스캔
  python3 -m htb_agent.main 10.129.1.5 --auto           # 범위내 자동승인
  python3 -m htb_agent.main 10.129.1.5 --attacker-ip 10.10.14.5
  python3 -m htb_agent.main 10.129.1.5 --range 10.129.0.0/16

주의: 실제 실행은 Kali + HTB VPN 환경에서. 대상은 '권한이 확인된 HTB 머신'만.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .scope_guard import ScopeGuard, ScopeViolation
from .environment import preflight, detect_vpn_ips
from .tools.runner import SubprocessRunner
from .tools.recon import auto_approve_in_scope
from .approval import interactive_approver
from .knowledge import KnowledgeBase
from .orchestrator import Orchestrator


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="htb-agent",
        description="HTB 머신 승인제 풀이 에이전트 (Kali). 권한 확인된 대상만.",
    )
    p.add_argument("target", help="대상 HTB 머신 IP (허용 대역 내)")
    p.add_argument("--range", action="append", dest="ranges",
                   help="허용 타겟 CIDR (반복 가능). 생략 시 HTB 기본 대역")
    p.add_argument("--attacker-ip", action="append", dest="attacker_ips",
                   help="공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지")
    p.add_argument("--cred", action="append", dest="creds",
                   help="레거시 자격증명 'user:pass[:domain]' (셸 이력에 남을 수 있음). "
                        "--username 또는 --credentials-file 권장")
    p.add_argument("--username", help="제공된 계정. 비밀번호는 숨김 입력으로 받음")
    p.add_argument("--domain", help="제공된 AD 도메인 (--username과 함께 사용)")
    p.add_argument("--credentials-file", help="자격증명 JSON 파일(object 또는 list)")
    p.add_argument("--require-llm", action="store_true",
                   help="선택 LLM을 사용할 수 없으면 스캔 전에 중단")
    p.add_argument("--config", help="설정 파일(.json/.yaml). 우선순위: CLI > 설정파일 > 기본값")
    p.add_argument("--auto", action="store_true",
                   help="범위내+검증통과 명령 자동승인 (비대화형)")
    # 아래 덮어쓰기 가능 옵션은 기본값 None → 설정파일/내장기본값과 병합
    p.add_argument("--max-attempts", type=int, default=None,
                   help="포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지)")
    p.add_argument("--max-enum", type=int, default=None,
                   help="enum 자동실행 최대 개수 (기본 6, 무한확장 방지)")
    p.add_argument("--max-rounds", type=int, default=None,
                   help="ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지)")
    p.add_argument("--knowledge", default=None,
                   help="지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장")
    p.add_argument("--llm", choices=["none", "claude", "ollama", "hybrid"], default=None,
                   help="LLM 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, "
                        "hybrid=로컬 기본+어려운 단계만 API(토큰 절감, 룰 2-5)")
    p.add_argument("--llm-tier", choices=["cheap", "standard", "strong"], default=None,
                   help="LLM 티어 (비용/성능)")
    p.add_argument("--token-budget", type=int, default=None,
                   help="과금 모델 누적 토큰 상한(입력+출력+캐시). 넘으면 LLM 호출을 막는다")
    p.add_argument("--no-one-day", action="store_true",
                   help="관측된 제품/버전의 로컬 SearchSploit 메타데이터 검색 비활성")
    p.add_argument("--online-cve", action="store_true",
                   help="관측된 제품/버전 또는 CVE만 NVD에 1회 조회 (기본은 외부 조회 안 함)")
    p.add_argument("--state-dir", default=None,
                   help="세션 상태 저장 디렉토리 (기본 ./state)")
    p.add_argument("--resume", action="store_true",
                   help="저장된 상태에서 재개 (RECON 재사용, 재스캔 생략)")
    p.add_argument("--no-save", action="store_true", help="상태 저장 안 함")
    p.add_argument("--log-file", default=None,
                   help="감사 로그(JSONL) 경로. 생략 시 <state-dir>/audit_<타겟>.jsonl")
    p.add_argument("--no-audit", action="store_true", help="감사 로그 비활성")
    p.add_argument("--writeup", nargs="?", const="__auto__", default=None,
                   help="풀이 라이트업 Markdown 생성(경로 생략 시 writeup_<타겟>.md)")
    p.add_argument("--writeup-format", choices=["htb", "tistory"], default="htb",
                   help="라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션)")
    p.add_argument("--runner", choices=["session", "oneshot"], default="session",
                   help="session(기본): 지속 셸 — cd·env 유지, 파이프/리다이렉트, pty, "
                        "백그라운드. oneshot: 명령마다 새 프로세스(shell 비경유)")
    return p


def _build_llm_router(kind: str, tier_name: str, token_budget: int | None = None):
    """LLM 백엔드 구성. 사용 불가면 (None, 사유) 반환."""
    if kind == "none":
        return None, "LLM 미사용(규칙기반)"
    from .llm.base import Tier
    from .llm.router import LLMRouter
    if kind == "claude":
        from .llm.claude_provider import ClaudeProvider
        provider = ClaudeProvider()
    elif kind == "hybrid":
        # 로컬(ollama) 기본 + 어려운 단계만 외부(claude) — 룰 [2-5] 토큰 절감.
        from .llm.ollama_provider import OllamaProvider
        from .llm.claude_provider import ClaudeProvider
        from .tiering import HybridProvider
        provider = HybridProvider(local=OllamaProvider(), external=ClaudeProvider())
    else:
        from .llm.ollama_provider import OllamaProvider
        provider = OllamaProvider()
    ok, reason = provider.available()
    if not ok:
        return None, f"{kind} 사용 불가: {reason}"
    return (LLMRouter(provider, default_tier=Tier(tier_name), token_budget=token_budget),
            f"{kind}({tier_name})")


def _build_runner(kind: str):
    """러너 선택. session 불가(pexpect/pty 없음)면 oneshot 으로 내려간다."""
    if kind == "oneshot":
        return SubprocessRunner(), "oneshot(shell 비경유)"
    try:
        from .tools.session import ShellSession, SessionError
        try:
            return ShellSession(), "session(지속 셸)"
        except SessionError as e:
            return SubprocessRunner(), f"oneshot 대체 — 세션 불가: {e}"
    except ImportError as e:
        return SubprocessRunner(), f"oneshot 대체 — pexpect 없음: {e}"


def main(argv: list[str] | None = None, runner=None) -> int:
    # runner 주입 가능(테스트). 주입 없으면 --runner 로 선택.
    args = build_parser().parse_args(argv)
    if args.domain and not args.username:
        print("⛔ --domain은 --username과 함께 사용하세요", file=sys.stderr)
        return 2
    if args.no_one_day and args.online_cve:
        print("⛔ --online-cve는 --no-one-day와 함께 사용할 수 없습니다", file=sys.stderr)
        return 2
    from .creds import CredentialVault, Credential
    try:
        vault = CredentialVault.from_cli(args.creds)
        if args.credentials_file:
            for cred in CredentialVault.load_file(args.credentials_file).creds:
                vault.add(cred)
        if args.username:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("제공된 계정 비밀번호: ")
            vault.add(Credential(args.username, password, args.domain, source="prompt"))
    except (ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning) as e:
        print(f"⛔ 자격증명 입력 오류: {e}", file=sys.stderr)
        return 2

    # 0) 설정 파일 로드 + 우선순위 해소 (CLI > config > 기본값)
    from .config import load_config, pick, Config, ConfigError
    try:
        cfg = load_config(args.config) if args.config else Config()
    except ConfigError as e:
        print(f"⛔ 설정 오류: {e}", file=sys.stderr)
        return 2
    ranges = pick(args.ranges, cfg.allowed_ranges, None)
    max_attempts = pick(args.max_attempts, cfg.max_attempts, 4)
    max_enum = pick(args.max_enum, cfg.max_enum, 6)
    max_rounds = pick(args.max_rounds, cfg.max_rounds, 2)
    knowledge_dir = pick(args.knowledge, cfg.knowledge_dir, "knowledge")
    llm_kind = pick(args.llm, cfg.llm_backend, "none")
    # 기본 'cheap' = 티어 정책(tiering.tier_for)의 하한. 열거는 저렴/로컬에서
    # 시작하고 단계·난이도에 따라 올라간다(룰 [2-5]). --llm-tier 로 하한을 올리면
    # 전부 그 티어 이상으로 강제된다.
    llm_tier = pick(args.llm_tier, cfg.llm_tier, "cheap")
    state_dir = pick(args.state_dir, cfg.state_dir, "state")
    token_budget = pick(args.token_budget, cfg.token_budget, None)

    # 1) Scope Guard 구성 + 타겟 바인딩
    guard = ScopeGuard.from_cidr_strings(ranges)
    try:
        guard.bind_target(args.target)
    except ScopeViolation as e:
        print(f"⛔ {e}", file=sys.stderr)
        return 2

    # 2) 공격자 VPN IP 등록 (지정 or 설정 or 자동탐지)
    attacker = pick(args.attacker_ips, cfg.attacker_ips, None) or detect_vpn_ips()
    for ip in attacker:
        try:
            guard.add_attacker_ip(ip)
        except ValueError as e:
            print(f"⚠️ 공격자 IP 무시: {e}", file=sys.stderr)

    # 3) 환경 프리플라이트
    pf = preflight(required_tool_keys=["nmap"])
    print(pf.render())
    print(f"\n타겟 바인딩: {guard.bound_target} | 허용대역: {guard.describe()} | 공격자IP: {attacker or '(없음)'}\n")

    # 4) 지식베이스 + 취약점 KB 로드 (사용자 학습데이터로 성장)
    kb = KnowledgeBase.load(base_dir=knowledge_dir)
    from .vuln import VulnKB
    vuln_kb = VulnKB.load(base_dir=knowledge_dir)
    print(f"지식베이스: 규칙 {len(kb.rules)}개, 노트 {len(kb.notes)}개, "
          f"취약점 규칙 {len(vuln_kb.rules)}개 로드\n")

    # 5) LLM 두뇌 구성(선택)
    llm_router, llm_status = _build_llm_router(llm_kind, llm_tier, token_budget)
    print(f"LLM: {llm_status}\n")
    if args.require_llm and llm_router is None:
        print("⛔ LLM 준비 실패 — API 키/백엔드 설정을 확인하세요", file=sys.stderr)
        return 2

    # 6) 상태 저장소 (중단/재개) + 자격증명 볼트
    from .state import StateStore
    store = None if args.no_save else StateStore(state_dir)
    if args.resume and store and store.exists(args.target):
        prior = store.load(args.target)
        if prior:
            print("재개할 저장 상태 발견:\n" + prior.summary() + "\n")
            if prior.credentials:
                print("저장된 자격증명은 메타데이터만 보관되며 재개 시 복원하지 않습니다. "
                      "필요하면 --username 또는 --credentials-file로 다시 입력하세요.\n")
    if vault.creds:
        print(f"자격증명 볼트: {[c.label() for c in vault.creds]}\n")

    # 6.5) 감사 로그
    from .audit import AuditLog, NullAudit
    import os as _os
    if args.no_audit:
        audit = NullAudit()
    else:
        log_path = args.log_file or _os.path.join(
            state_dir, f"audit_{StateStore._safe(args.target)}.jsonl")
        audit = AuditLog(log_path, secrets=vault.secret_values())
        print(f"감사 로그: {log_path}\n")
    from .research import OneDayResearch
    one_day = None if args.no_one_day else OneDayResearch(online=args.online_cve, audit=audit)

    # 7) 오케스트레이션 (유한 단계: RECON→PROFILE→ENUM→(LLM)→REPORT)
    approver = auto_approve_in_scope if args.auto else interactive_approver
    if runner is None:
        runner, runner_desc = _build_runner(args.runner)
        print(f"러너: {runner_desc}\n")
    orchestrator = Orchestrator(guard, runner, kb, approver,
                                max_enum=max_enum,
                                recon_max_attempts=max_attempts,
                                max_rounds=max_rounds,
                                llm_router=llm_router, vuln_kb=vuln_kb,
                                vault=vault if vault.creds else None,
                                state_store=store, resume=args.resume, audit=audit,
                                one_day_research=one_day,
                                enable_one_day=not args.no_one_day)
    try:
        report = orchestrator.run()
    finally:
        if hasattr(runner, "close"):
            runner.close()
    print("\n" + report.summary())
    if llm_router is not None and llm_router.calls:
        print("\n" + llm_router.cost_summary())

    # 8) 라이트업 생성(선택)
    if args.writeup is not None:
        from .writeup import generate_writeup, generate_tistory
        from .state import StateStore
        gen = generate_tistory if args.writeup_format == "tistory" else generate_writeup
        md = gen(report, attacker_ip=(attacker[0] if attacker else None))
        path = (args.writeup if args.writeup != "__auto__"
                else f"writeup_{StateStore._safe(args.target)}.md")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"\n라이트업 생성: {path}")
        except OSError as e:
            print(f"\n⚠️ 라이트업 저장 실패: {e}", file=sys.stderr)

    return 0 if report.status == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
