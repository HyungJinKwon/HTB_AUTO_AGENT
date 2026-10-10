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
import shutil
import sys

from . import __version__
from .approval import interactive_approver
from .environment import detect_vpn_ips, preflight
from .knowledge import KnowledgeBase
from .orchestrator import _FIXED_POINT_CAP, Orchestrator
from .profiles import JEOPARDY_CATEGORIES
from .scope_guard import ScopeGuard, ScopeViolation
from .tools.recon import auto_approve_in_scope
from .tools.runner import SubprocessRunner

_HELP_EPILOG = """\
처음 사용하는 순서:
  1) assassin --doctor            도구·VPN·LLM 준비 상태 점검(빨간 항목만 채우면 됨)
  2) assassin --setup-llm         (선택) Claude·로컬 LLM 연결 마법사
  3) assassin 10.129.x.x          HTB 머신 풀이 시작(위험한 명령만 물어봄)

자주 쓰는 예:
  assassin 10.129.x.x --manual                            모든 명령을 보며 배우기
  assassin 10.129.x.x --autonomous --time-budget 45 --html 해커톤: 최대 자율 + 시간 제한
  assassin chall.host:1337 --platform ctf --category web  CTF 문제
  assassin 10.129.x.x --resume                            중단한 곳부터 이어서

자세한 안내: docs/QUICKSTART.md (1쪽) · docs/USAGE.md
"""


class _SuggestingParser(argparse.ArgumentParser):
    """알 수 없는 옵션에 '가장 가까운 실제 옵션'을 제안(초보자 오타 바로잡기). 예:
    'assassin 10.129.1.5 --autonomus' → "'--autonomus' → 혹시 '--autonomous'?" """
    def error(self, message):   # noqa: A003 (argparse 시그니처)
        if message.startswith("unrecognized arguments:"):
            import difflib
            opts = [o for a in self._actions for o in a.option_strings]
            hints = []
            for tok in message.split(":", 1)[1].split():
                if tok.startswith("-"):
                    near = difflib.get_close_matches(tok, opts, n=1, cutoff=0.6)
                    if near:
                        hints.append(f"'{tok}' → 혹시 '{near[0]}'?")
            if hints:
                message += "\n  " + " · ".join(hints) + "   (전체 옵션: assassin --help)"
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    p = _SuggestingParser(
        prog="assassin",
        usage="assassin <타겟> [옵션]      (처음이면: assassin --doctor)",
        description="ASSASSIN — HTB·CTF 승인제 자동 풀이 에이전트 (Kali). 권한이 확인된 대상에서만 사용하세요.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    # 초보자용 그룹(도움말 표시 순서). 처음 보는 사람은 '시작하기'만 보면 된다.
    g_start = p.add_argument_group("시작하기 (처음이면 여기부터)")
    g_target = p.add_argument_group("대상 · 플랫폼")
    g_mode = p.add_argument_group("실행 방식 (승인 · 재개)")
    g_llm = p.add_argument_group("LLM 두뇌 (선택 — 연결은 --setup-llm)")
    g_limit = p.add_argument_group("시간 · 한도")
    g_out = p.add_argument_group("결과물 · 기록")
    g_kb = p.add_argument_group("지식 · 학습 · 수집")
    g_tool = p.add_argument_group("단독 도구 (타겟 없이 실행 · 생성만 하는 도구 포함)")
    g_start.add_argument("-h", "--help", action="help", help="이 도움말을 보여 주고 끝냄")
    g_start.add_argument("--version", action="version", version=f"ASSASSIN {__version__}",
                         help="버전 표시")
    g_start.add_argument("--doctor", action="store_true",
                   help="환경 자가진단(도구·LLM·VPN 점검, 스캔 안 함). 완전 초보자 권장 첫 실행")
    g_start.add_argument("--install-missing", nargs="?", const="__all__", default=None,
                   dest="install_missing", metavar="CATS",
                   help="빠진 보안 도구를 install_tools.sh 로 자동 설치(카테고리 지정 가능: "
                        "'recon web smb …'). 저장소의 공식 스크립트만 실행, 루트 필요")
    g_start.add_argument("--setup-llm", action="store_true", dest="setup_llm",
                   help="LLM 연결 마법사: Claude(API 키)·로컬 LLM(Ollama 모델)을 질문에 답하며 연결하고 "
                        "실제 1회 호출로 확인 → 기본 설정 저장(이후 --llm 생략 가능). 키는 ~/.config/assassin 에 600 권한")
    g_start.add_argument("--llm-test", action="store_true", dest="llm_test",
                   help="환경 자가진단 + LLM 실제 호출 테스트(짧은 요청 1회 — 틀린 키·없는 모델·막힌 네트워크 확인)")
    g_tool.add_argument("--revshell", metavar="LHOST:LPORT", default=None,
                   help="리버스쉘 페이로드 생성(실행 안 함). 'IP:PORT' 또는 'PORT'"
                        "(공격자 IP 자동/--attacker-ip). 권한 확인 대상 전용")
    g_tool.add_argument("--learn", metavar="TOPIC", default=None,
                   help="권위 출처 자가학습(도구·공격기법·개념·프로토콜)을 지식베이스에 저장. "
                        "예: --learn kerberoasting / burp / http. 전체 일괄: --learn all. 목록: --learn list")
    g_tool.add_argument("--promote", metavar="TOPIC", default=None,
                   help="로컬 학습 노트(learned-<주제>.md) 중 품질 관문을 통과한 항목을 번들 시드의 "
                        "'최신 보강(승격)' 섹션으로 승격. 결과를 커밋·PR 하면 모든 사용자에게 공유. "
                        "예: --promote sqli / 전체: --promote all")
    g_kb.add_argument("--list-sessions", action="store_true", dest="list_sessions",
                   help="저장된 세션(타겟) 목록 출력 — --resume 대상 확인용(타겟 없이 단독 실행)")
    g_kb.add_argument("--kb-sync", action="store_true", dest="kb_sync",
                   help="공유 저장소의 최신 번들 시드를 지금 동기화(검증 통과분만 로컬 캐시에 적용). "
                        "타겟 실행 시에는 하루 1회 자동")
    g_kb.add_argument("--update", action="store_true",
                   help="최신화 원클릭: 공유 시드 동기화 + 권위출처 재학습·승격(--offline 이면 네트워크 생략)")
    g_kb.add_argument("--export-stats", dest="export_stats", default=None, metavar="파일",
                   help="실행 학습 통계(변형 성공률) 내보내기 — 성장 공유용(명령 전체·타겟·출력 미포함)")
    g_kb.add_argument("--import-stats", dest="import_stats", default=None, metavar="파일",
                   help="공유된 실행 학습 통계를 로컬에 병합(성장 공유 — succ/att 합산)")
    g_kb.add_argument("--no-kb-sync", action="store_true", dest="no_kb_sync",
                   help="실행 시 공유 시드 자동 동기화 끄기(환경변수 ASSASSIN_NO_KB_SYNC=1 도 동일)")
    g_tool.add_argument("--ingest", metavar="PATH", default=None,
                   help="사용자 제공 자료(.md/.txt/.pdf 파일 또는 디렉터리)를 지식베이스 노트로 "
                        "미리 학습. 예: --ingest ./my-writeups/")
    g_tool.add_argument("--cloud", metavar="NAME", default=None,
                   help="AWS/S3 열거 자동 준비(생성 안 실행). 호스트명/도메인에서 버킷명 "
                        "후보+비인증 점검 생성. 예: --cloud acme.htb. 권한 확인 자산 전용")
    g_tool.add_argument("--privesc", metavar="OS", default=None,
                   choices=["linux", "windows", "windows_ad"],
                   help="권한상승 플레이북 자동 준비(생성 안 실행). OS 별 열거·점검·LPE "
                        "체크리스트 생성. 예: --privesc linux. 획득한 대상 셸에서 직접 실행")
    g_tool.add_argument("--crack", metavar="HASH", default=None,
                   help="해시 크래킹 자동 준비(생성 안 실행). 해시 종류 식별 + john/hashcat "
                        "명령 생성. 예: --crack '$krb5tgs$23$...'. 권한 확인 자산 해시 전용")
    g_tool.add_argument("--bench", metavar="SUITE", nargs="?", const="__default__", default=None,
                   help="로컬 모의 문제로 풀이 성공률·명령 수·시간·비용 측정(오프라인, 실제 통신 없음). "
                        "SUITE 생략 시 번들 문제 세트. --attempts N 으로 반복(pass@N), --llm 으로 LLM 비교")
    g_tool.add_argument("--attempts", type=int, default=1, metavar="N",
                   help="--bench/--live-bench 에서 문제당 시도 횟수(기본 1)")
    g_tool.add_argument("--live-bench", metavar="DIR", nargs="?", const="__default__", default=None,
                   help="실제 서비스(loopback 파이썬 / docker 컨테이너 / vm 외부·가상머신)를 띄우거나 붙어 진짜 도구로 풀이 — "
                        "성공률·검증된 풀이율·시간 측정. DIR 생략 시 bench/live. docker 타겟은 데몬 필요. "
                        "--attempts·--llm 적용")
    g_tool.add_argument("--replay", metavar="JSONL", default=None,
                   help="감사 로그(JSONL)를 단계별 재생 HTML 로 변환(이전/다음/자동 재생). "
                        "예: --replay state/audit_10.129.1.5.jsonl → 같은 이름의 .html")
    g_start.add_argument("target", nargs="?", default=None,
                   help="대상(IP 또는 호스트명/URL). HTB=허용대역 내 IP, "
                   "CTF/Dreamhack=챌린지 host:port/URL")
    g_target.add_argument("--platform", choices=["htb", "dreamhack", "ctf"], default=None,
                   help="플랫폼 프로파일 (기본 htb). dreamhack/ctf=단일 타겟+flag{} 모드")
    g_target.add_argument("--category", choices=[k for k, _ in JEOPARDY_CATEGORIES], default=None,
                   help="Jeopardy 카테고리 힌트(web/pwn/rev/crypto/forensic/misc). "
                        "CTF/Dreamhack 에서 LLM 제안을 카테고리에 맞게 유도")
    g_target.add_argument("--flag-prefix", action="append", dest="flag_prefixes", metavar="PREFIX",
                   help="우선 인식할 플래그 접두 (반복 가능, 예: --flag-prefix DH). "
                        "플랫폼 기본값에 추가")
    g_target.add_argument("--range", action="append", dest="ranges", metavar="CIDR",
                   help="허용 타겟 CIDR (반복 가능). 생략 시 플랫폼 기본(HTB만 대역 강제)")
    g_target.add_argument("--attacker-ip", action="append", dest="attacker_ips", metavar="IP",
                   help="공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지")
    g_target.add_argument("--files", action="append", dest="files", metavar="PATH",
                   help="챌린지 첨부파일/디렉터리(반복 가능, zip·tar 는 안전하게 풀어 둠). "
                        "작업공간 files/ 에 복사되어 LLM 이 소스를 읽고 분석. 포트가 없어도 파일 분석으로 진행")
    g_target.add_argument("--lport", type=int, default=4444, metavar="PORT",
                   help="리버스쉘 리스너 포트(자동 준비 페이로드용, 기본 4444)")
    g_target.add_argument("--cred", action="append", dest="creds", metavar="USER:PASS",
                   help="자격증명 'user:pass' / 'user:pass:domain' / "
                        "'user:pass:domain:nthash' (반복 가능). Pass-the-Hash 는 "
                        "'user:<32hex>' 또는 'user::domain:<NT|LM:NT>'. "
                        "{user}/{pass}/{domain}/{hash} 제안을 실행 후보로 승격")
    g_target.add_argument("--cred-file", dest="cred_file", default=None, metavar="경로",
                   help="자격증명 JSON 파일에서 일괄 로드(인라인 --cred 와 함께 사용 가능). "
                        "형식: {\"username\":..,\"password\":..,\"domain\":..,\"nt_hash\":..} 또는 그 목록")
    g_mode.add_argument("--config", help="설정 파일(.json/.yaml). 우선순위: CLI > 설정파일 > 기본값")
    g_mode.add_argument("--autonomous", "--hackathon", action="store_true", dest="autonomous",
                   help="능동적 완전자동 모드: 범위내 자동승인 + 깊은 재진입 스윕 + 병렬 열거 + "
                        "변형학습 + 전 자동준비. 목표(flag/root)까지 스스로 추진(안전 게이트 유지)")
    g_mode.add_argument("--poc", action="append", dest="poc_commands", metavar="CMD",
                   help="옵트인: searchsploit 결과에서 고른 '공개 PoC 한 줄'을 게이트로 실행"
                        "(반복 가능). 권한 확인 대상 전용. 버전 대조 후 사용")
    g_mode.add_argument("--auto-poc", action="store_true", dest="auto_poc",
                    help="⭐ 버전매칭 1순위 PoC 실행계획을 자동으로 --poc 큐에 투입(권한 확인 대상 전용)")
    g_mode.add_argument("--sandbox", choices=["none", "shell", "docker", "vm"], default=None,
                   help="명령을 '어디서' 실행할지: none=로컬 셸 비경유(기본, 파이프 불가) · "
                        "shell=로컬 bash(파이프 O, 네트워크 강제 X) · docker=Kali 컨테이너+egress 방화벽 · "
                        "vm=SSH 로 접속한 가상머신/공격호스트. 스크립트 작성·동적 실행 자동은 "
                        "egress 강제된 docker 또는 'vm --vm-confine' 에서만")
    g_mode.add_argument("--sandbox-image", default=None, metavar="IMAGE",
                   help="docker 샌드박스 이미지(기본 assassin-sandbox:latest — scripts/build_sandbox.sh)")
    g_mode.add_argument("--vm-ssh", default=None, metavar="USER@HOST",
                   help="--sandbox vm: 명령을 실행할 VM 의 SSH 접속 대상(예: kali@192.168.56.10)")
    g_mode.add_argument("--vm-ssh-key", default=None, metavar="KEYFILE",
                   help="--sandbox vm: SSH 개인키 파일(미지정 시 ssh 기본·에이전트 사용)")
    g_mode.add_argument("--vm-ssh-port", type=int, default=None, metavar="PORT",
                   help="--sandbox vm: SSH 포트(기본 22)")
    g_mode.add_argument("--vm-sudo", action="store_true",
                   help="--sandbox vm: VM 에서 egress 정책 적용 등에 sudo 사용(--vm-confine 과 함께)")
    g_mode.add_argument("--vm-confine", action="store_true",
                   help="--sandbox vm: 접속한 VM 에 egress 방화벽(타겟 대역만)을 적용해 docker 처럼 "
                        "완전자율 동적 실행을 자동 허용. 그 VM 네트워크를 타겟으로 제한하므로 전용 풀이 VM 에서만")
    g_mode.add_argument("--auto", action="store_true",
                   help="완전 자동: 범위내+검증통과만 실행, 범위 밖은 조용히 건너뜀(무프롬프트)")
    g_mode.add_argument("--manual", action="store_true",
                   help="완전 수동: 모든 명령을 실행 전 확인(승인제 최대)")
    g_mode.add_argument("--dry-run", action="store_true", dest="dry_run",
                   help="계획 미리보기: 정찰·분석은 하되 제안된 명령은 '실행하지 않고' 보여만 준다(무해 점검)")
    g_mode.add_argument("--exploit-exec", action="store_true", dest="exploit_exec",
                   help="옵트인(기본 OFF): 확보한 평문 자격으로 SSH 접속해 플래그 읽기·권한상승 "
                        "열거를 게이트를 거쳐 자동 실행(권한 확인 대상 전용)")
    g_kb.add_argument("--no-enrich", action="store_true",
                   help="CVE/CWE 자동 수집(NVD/GitHub) 비활성")
    g_kb.add_argument("--learn-gaps", action="store_true", dest="learn_gaps",
                   help="자율 지식 획득: 풀이 중 모르는 기술을 권위 출처에서 자동 학습해 "
                        "KB 에 즉시 반영(allowlist·P1 유지). autonomous 모드에선 기본 활성")
    g_kb.add_argument("--no-learn-gaps", action="store_true", dest="no_learn_gaps",
                   help="자율 지식 획득 비활성(autonomous 모드에서도 끔)")
    g_kb.add_argument("--web-learn", action="store_true", dest="web_learn",
                   help="인터넷 검색 학습: 카탈로그 밖 '미해석 공백'을 웹 검색으로 학습해 "
                        "KB 반영(--learn-gaps 를 함께 켬). HTB 라이트업(공식·제3자)은 가드로 차단. autonomous 기본 활성")
    g_kb.add_argument("--no-web-learn", action="store_true", dest="no_web_learn",
                   help="인터넷 검색 학습 비활성(autonomous 모드에서도 끔)")
    g_kb.add_argument("--offline", action="store_true",
                   help="오프라인: 네트워크 수집 금지(캐시만 사용)")
    g_kb.add_argument("--enrich-cache", default=None,
                   help="CVE 캐시 디렉토리 (기본 <knowledge>/cve_cache)")
    # 아래 덮어쓰기 가능 옵션은 기본값 None → 설정파일/내장기본값과 병합
    g_limit.add_argument("--max-attempts", type=int, default=None,
                   help="포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지)")
    g_limit.add_argument("--max-enum", type=int, default=None,
                   help="enum 자동실행 최대 개수 (기본 6, 무한확장 방지)")
    g_limit.add_argument("--max-llm", type=int, default=None,
                   help="LLM 제안 명령 최대 개수 (기본 5, 자율모드 8)")
    g_limit.add_argument("--max-rounds", type=int, default=None,
                   help="ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지)")
    g_limit.add_argument("--max-sweeps", type=int, default=None,
                   help="단계 재진입 스윕 수 (기본 2). 새 관측·크리덴셜로 이전 단계 "
                        "재시도. 상태 정체 시 조기종료(유한)")
    g_limit.add_argument("--max-parallel", type=int, default=None,
                   help="열거 명령 동시 실행 수 (기본 1=순차). 독립 명령의 I/O 만 "
                        "병렬 — 게이트·결과처리는 순차로 안전")
    g_limit.add_argument("--variants", type=int, default=None,
                   help="명령당 옵션 조합 변형 수 (기본 2, 1=변형끔). 경우의 수 시도")
    g_limit.add_argument("--time-budget", type=float, default=None, metavar="분",
                   help="해커톤 시간 예산(분). 마감이 되면 진행 중 단계를 마치고 남은 단계를 "
                        "생략한 뒤 상태를 저장한다(--resume 으로 이어감). 기본: 무제한")
    g_llm.add_argument("--max-cost", type=float, default=None, metavar="USD",
                   help="LLM 누적 추정 비용 상한(달러). 넘으면 LLM 호출을 멈추고 규칙 기반으로 "
                        "계속 진행한다. 기본: 무제한")
    g_mode.add_argument("--observe", action="store_true",
                   help="사람 관찰 입력: 건너뛴(미승인) 명령 대신 브라우저 등으로 직접 확인한 내용을 "
                        "적어 기록에 반영한다('사람 관찰'로 표시, 에이전트 검증 결과와 구분). 대화형 실행용")
    g_kb.add_argument("--knowledge", default=None,
                   help="지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장")
    g_llm.add_argument("--llm", choices=["none", "claude", "ollama", "hybrid"], default=None,
                   help="LLM 두뇌 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, "
                        "hybrid=둘을 단계 난이도로 라우팅+폴백·연속 오류 백엔드 차단·라우팅 집계")
    g_llm.add_argument("--llm-tier", choices=["cheap", "standard", "strong"], default=None,
                   help="LLM 기본 티어(기본 standard). 명령 생성은 단계별 티어 우선"
                        "(열거=cheap·침투=standard·권한상승/측면=strong), 저확신 시 자동 승격")
    g_out.add_argument("--state-dir", default=None,
                   help="세션 상태 저장 디렉토리 (기본 ./state)")
    g_mode.add_argument("--resume", action="store_true",
                   help="저장된 상태에서 재개 (RECON 재사용 · 실행된 명령·결과·플래그 복원, "
                        "다시 실행 안 함). Ctrl+C 로 중단한 세션도 이어감")
    g_out.add_argument("--no-save", action="store_true", help="상태 저장 안 함")
    g_out.add_argument("--log-file", default=None,
                   help="감사 로그(JSONL) 경로. 생략 시 <state-dir>/audit_<타겟>.jsonl")
    g_out.add_argument("--no-audit", action="store_true", help="감사 로그 비활성")
    g_out.add_argument("--writeup", nargs="?", const="__auto__", default=None,
                   help="풀이 라이트업 Markdown 생성(경로 생략 시 writeup_<타겟>.md)")
    g_out.add_argument("--writeup-format", choices=["htb", "tistory"], default="htb",
                   help="라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션)")
    g_out.add_argument("--json", nargs="?", const="__auto__", default=None, dest="json_out",
                   help="결과를 기계판독 JSON 으로 내보내기(경로 생략 시 <state-dir>/report_<타겟>.json)")
    g_out.add_argument("--html", nargs="?", const="__auto__", default=None, dest="html_out",
                   help="결과를 HTML 대시보드로 내보내기(블루/네이비, 경로 생략 시 <state-dir>/report_<타겟>.html)")
    return p


def _start_guide() -> str:
    """인자 없이 실행했을 때의 초보자 시작 안내(긴 usage 대신)."""
    from . import ui
    return ui.panel("ASSASSIN 시작하기 — 타겟이 필요합니다", [
        ui.accent2("1) ") + ui.bold("assassin --doctor") + ui.dim("        준비 상태 점검(도구·VPN·LLM)"),
        ui.accent2("2) ") + ui.bold("assassin --setup-llm") + ui.dim("     (선택) LLM 연결 마법사"),
        ui.accent2("3) ") + ui.bold("assassin 10.129.x.x")
        + ui.dim("      풀이 시작(위험한 것만 y/n 확인)"),
        "",
        ui.accent2("완전 자동(무프롬프트): ") + ui.bold("assassin 10.129.x.x --autonomous")
        + ui.dim("   → 끝까지 자동 진행 후 결과·플래그 값 출력"),
        ui.dim("배우며 실행:   assassin 10.129.x.x --manual   (모든 명령을 보고 승인)"),
        ui.dim("격리 실행:     --sandbox docker   또는   --sandbox vm --vm-ssh user@host"),
        ui.dim("CTF 문제:      assassin chall.host:1337 --platform ctf"),
        ui.dim("이어서 하기:   assassin 10.129.x.x --resume"),
        ui.dim("전체 옵션:     assassin --help    ·    1쪽 안내: docs/QUICKSTART.md"),
    ], style="navy")


def _scope_hint(err: str, target: str, platform: str) -> list[str]:
    """타겟 바인딩 실패 시 초보자가 바로 고칠 수 있는 다음 명령(범위 판단은 바꾸지 않음)."""
    hints = []
    if "IPv6" in err:
        hints.append("현재 IPv4 타겟만 지원합니다 — HTB 머신은 IPv4 입니다(머신 페이지의 Target IP).")
    elif "호스트명" in err or "파싱 실패" in err:
        hints.append(f"CTF/Dreamhack 문제(호스트명·URL)면:  assassin {target} --platform ctf")
        hints.append("HTB 머신이면 IP 로 입력하세요(예: 10.129.x.x) — 머신 페이지의 Target IP")
    elif "대역" in err and platform == "htb":
        # 대상 IP 를 그대로 넣은 명령은 만들지 않는다(공인 IP 를 우회하라는 뜻으로 읽히지 않게)
        hints.append("권한이 확인된 대상만 가능합니다 — 공인 IP·남의 서버는 대상이 아닙니다")
        hints.append("HTB 머신이면 VPN 연결 후 머신 페이지의 Target IP(10.10.x.x / 10.129.x.x)를 넣으세요")
        hints.append("본인 소유 실습 환경·CTF 문제면:  --platform ctf  (또는 HTB 랩 대역은 --range <CIDR>)")
    return hints


def _ollama_opts(cfg) -> dict:
    """설정 파일의 Ollama 모델/주소(값이 있을 때만) — _build_llm_router 키워드 인자로."""
    opts = {}
    if getattr(cfg, "llm_ollama_model", None):
        opts["ollama_model"] = cfg.llm_ollama_model
    if getattr(cfg, "llm_ollama_host", None):
        opts["ollama_host"] = cfg.llm_ollama_host
    return opts


def _ollama_provider(ollama_model: str = "", ollama_host: str = ""):
    """OllamaProvider — 우선순위: 환경변수(OLLAMA_HOST/OLLAMA_MODEL) > 설정 파일 > 기본값."""
    import os as _os

    from .llm.base import Tier
    from .llm.ollama_provider import OllamaProvider
    host = _os.environ.get("OLLAMA_HOST") or ollama_host or None
    models = ({t: ollama_model for t in Tier}
              if ollama_model and not _os.environ.get("OLLAMA_MODEL") else None)
    return OllamaProvider(host=host, models=models)


def _build_llm_router(kind: str, tier_name: str, ollama_model: str = "", ollama_host: str = ""):
    """LLM 백엔드 구성. 사용 불가면 (None, 사유) 반환."""
    if kind == "none":
        return None, "LLM 미사용(규칙기반)"
    from .llm.base import Tier
    from .llm.claude_provider import ClaudeProvider
    from .llm.router import HybridRouter, LLMRouter

    def _mk(provider):
        ok, reason = provider.available()
        return (LLMRouter(provider, default_tier=Tier(tier_name)) if ok else None), reason

    if kind == "hybrid":
        # 두 백엔드를 단계 난이도로 라우팅 + 상호 폴백(장점극대·단점보완)
        local, lreason = _mk(_ollama_provider(ollama_model, ollama_host))   # 열거·일반 → 무료·토큰절약
        strong, sreason = _mk(ClaudeProvider())    # 권한상승·exploit → 정확
        if local is None and strong is None:
            return None, (f"hybrid 사용 불가: ollama({lreason}) / claude({sreason})"
                          " — 연결 마법사: assassin --setup-llm")
        status = (f"hybrid(local=ollama[{'OK' if local else 'X'}], "
                  f"strong=claude[{'OK' if strong else 'X'}], 티어={tier_name})")
        if local is not None:
            # 티어 모델 미설치 시 설치 모델로 대체됨을 알림(강력 단계 품질이 낮아질 수 있음)
            p = local.provider
            subs = [f"{t.value}→{p.model_for(t)}" for t in Tier
                    if p.model_for(t) != p.models.get(t)]
            if subs:
                status += " · 로컬 모델 대체: " + ", ".join(subs)
        return HybridRouter(local=local, strong=strong,
                            default_tier=Tier(tier_name)), status

    provider = ClaudeProvider() if kind == "claude" else _ollama_provider(ollama_model, ollama_host)
    router, reason = _mk(provider)
    if router is None:
        return None, f"{kind} 사용 불가: {reason} — 연결 마법사: assassin --setup-llm"
    return router, f"{kind}({tier_name})"


def _run_bench(args, cfg, knowledge_dir: str) -> int:
    """--bench: 모의 문제 세트를 시도하고 표·JSON·시도별 감사 로그(--replay 용)를 남긴다."""
    import json as _json
    import os as _os
    from datetime import datetime

    from . import bench, ui
    from .config import pick
    from .knowledge import KnowledgeBase
    suite = bench.default_suite_dir() if args.bench == "__default__" else args.bench
    try:
        challenges = bench.load_suite(suite)
    except bench.BenchError as e:
        print(ui.mark_err(f"벤치 문제 오류: {e}"), file=sys.stderr)
        return 2
    llm_kind = pick(args.llm, cfg.llm_backend, "none")
    router, llm_status = _build_llm_router(llm_kind, pick(args.llm_tier, cfg.llm_tier, "standard"),
                                           **_ollama_opts(cfg))
    if llm_kind != "none" and router is None:
        print(ui.mark_err(llm_status), file=sys.stderr)
        return 2
    state_dir = pick(args.state_dir, cfg.state_dir, "state")
    run_dir = _os.path.join(state_dir, "bench", datetime.now().strftime("%Y%m%d-%H%M%S"))
    print(ui.kv("문제 세트", f"{suite} · {len(challenges)}개 · 문제당 {max(1, args.attempts)}회", 10))
    print(ui.kv("LLM", llm_status, 10) + "\n")
    results = bench.run_bench(challenges, args.attempts, KnowledgeBase.load(base_dir=knowledge_dir),
                              router=router, trace_dir=run_dir,
                              progress=lambda m: print(ui.dim("  · " + m)))
    stats = bench.summarize(challenges, results)
    print("\n" + bench.render(stats, max(1, args.attempts), llm_kind))
    out = _os.path.join(run_dir, "results.json")
    with open(out, "w", encoding="utf-8") as f:
        _json.dump(bench.to_dict(suite, max(1, args.attempts), llm_kind, stats, results),
                   f, ensure_ascii=False, indent=2)
    print(ui.kv("결과", out, 10))
    print(ui.kv("재생", f"assassin --replay {_os.path.join(run_dir, '<문제>_<회차>.jsonl')}", 10))
    return 0


def _run_live_bench(args, cfg, knowledge_dir: str) -> int:
    """--live-bench: 실제 서비스를 띄우고 '진짜' 에이전트를 돌려 풀이율을 측정한다.
    집계·표·JSON·시도별 감사 로그는 오프라인 --bench 와 같은 구조를 재사용한다."""
    import json as _json
    import os as _os
    from datetime import datetime

    from . import bench, livebench, ui
    from .config import pick
    from .knowledge import KnowledgeBase
    suite = "bench/live" if args.live_bench == "__default__" else args.live_bench
    if not _os.path.isdir(suite):
        alt = _os.path.join(_os.path.dirname(__file__), "..", "..", "bench", "live")
        suite = suite if _os.path.isdir(suite) else _os.path.normpath(alt)
    try:
        challenges = livebench.load_live_suite(suite)
    except livebench.LiveBenchError as e:
        print(ui.mark_err(f"라이브 벤치 문제 오류: {e}"), file=sys.stderr)
        return 2
    # docker 타겟은 데몬이 '실제로 응답'해야 실행(없으면 명확히 알리고 건너뜀).
    # vm 타겟은 주소(challenge.address 또는 ASSASSIN_VM_<이름>)가 있어야 실행.
    has_docker = livebench.docker_available()
    runnable: list = []
    skipped: list = []
    for c in challenges:
        if c.kind == "loopback":
            runnable.append(c)
        elif c.kind == "docker":
            (runnable if has_docker else skipped).append(c)
        elif c.kind == "vm":
            addr = _os.environ.get(livebench.vm_env_key(c.name)) or c.address
            (runnable if addr else skipped).append(c)
        else:
            skipped.append(c)
    llm_kind = pick(args.llm, cfg.llm_backend, "none")
    router, llm_status = _build_llm_router(llm_kind, pick(args.llm_tier, cfg.llm_tier, "standard"),
                                           **_ollama_opts(cfg))
    if llm_kind != "none" and router is None:
        print(ui.mark_err(llm_status), file=sys.stderr)
        return 2
    state_dir = pick(args.state_dir, cfg.state_dir, "state")
    run_dir = _os.path.join(state_dir, "livebench", datetime.now().strftime("%Y%m%d-%H%M%S"))
    print(ui.kv("라이브 문제", f"{suite} · 실행 {len(runnable)}개"
                + (f" · 건너뜀 {len(skipped)}개" if skipped else "")
                + f" · 문제당 {max(1, args.attempts)}회", 10))
    print(ui.kv("LLM", llm_status, 10))
    print(ui.kv("실행", ui.warn("실제 서비스 기동 + 진짜 도구 실행 — 권한 확인 자산에서만"), 10) + "\n")
    if skipped:
        print(ui.dim("  건너뜀: " + ", ".join(f"{c.name}({c.kind})" for c in skipped)
                     + "  — docker 는 데몬 필요(./scripts/build_sandbox.sh 와 동일 환경), "
                     + "vm 은 challenge.address 또는 ASSASSIN_VM_<이름>=<IP> 필요"))
    results = livebench.run_live_bench(
        runnable, args.attempts, KnowledgeBase.load(base_dir=knowledge_dir),
        router=router, trace_dir=run_dir, progress=lambda m: print(ui.dim("  · " + m)))
    stats = bench.summarize(runnable, results)
    print("\n" + bench.render(stats, max(1, args.attempts), llm_kind))
    out = _os.path.join(run_dir, "results.json")
    _os.makedirs(run_dir, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        _json.dump(bench.to_dict(suite, max(1, args.attempts), llm_kind, stats, results),
                   f, ensure_ascii=False, indent=2)
    print(ui.kv("결과", out, 10))
    return 0 if any(r.solved for r in results) else 1


def _default_knowledge_dir() -> str:
    """지식베이스 폴더 기본값을 '실행한 폴더'가 아니라 '어디서 실행해도' 찾도록 해석한다.
    우선순위: ./knowledge(현재 폴더) → 패키지에 번들된 knowledge/(설치본·다른 cwd 안전)."""
    import os as _os
    cwd = _os.path.join(_os.getcwd(), "knowledge")
    if _os.path.isdir(cwd):
        return cwd
    bundled = _os.path.normpath(_os.path.join(_os.path.dirname(__file__), "..", "..", "knowledge"))
    if _os.path.isdir(bundled):
        return bundled
    # 패키지 안에 동봉된 경우(src/htb_agent/knowledge) — 휠 설치 대비
    inpkg = _os.path.join(_os.path.dirname(__file__), "knowledge")
    return inpkg if _os.path.isdir(inpkg) else cwd


def _print_kb_sync(r, verbose: bool = False) -> None:
    """공유 시드 동기화 결과 한 줄 요약(변화 없으면 자동 실행 시엔 조용히)."""
    from . import ui
    if r.applied or r.cleared or verbose:
        print(ui.kv("공유 시드", f"최신 반영 {len(r.applied)}개 · 로컬 최신 {len(r.cleared)}개 · "
                                 f"거부 {len(r.rejected)}개"))
    for name, reason in r.rejected:
        print(ui.dim(f"     ✗ {name} — {reason}"))


def _run_target(args, cfg, knowledge_dir, runner) -> int:
    """타겟 1개에 대한 전체 실행 경로(프로파일→가드→오케스트레이터→리포트/내보내기).
    main() 에서 분리 — 단독 명령 디스패치와 분리해 CLI 진입부를 얇게 유지."""
    from . import ui
    from .config import pick
    from .profiles import get_profile

    # 플랫폼 프로파일(HTB/Dreamhack/CTF)
    try:
        profile = get_profile(pick(args.platform, cfg.platform, "htb"))
    except ValueError as e:
        print(ui.mark_err(str(e)), file=sys.stderr)
        return 2
    print(ui.banner(profile.banner_subtitle))
    flag_prefixes = tuple(profile.flag_prefixes) + tuple(args.flag_prefixes or ())
    ranges = pick(args.ranges, cfg.allowed_ranges,
                  list(profile.default_ranges) or None)
    # 능동적 완전자동 모드: 명시 지정이 없으면 공격적 기본값으로 상향(한 명령 자율 풀이)
    def _auto_def(cli, cf, aggressive, base):
        return pick(cli, cf, aggressive if args.autonomous else base)
    max_attempts = pick(args.max_attempts, cfg.max_attempts, 4)
    max_enum = _auto_def(args.max_enum, cfg.max_enum, 24, 6)
    max_llm = _auto_def(args.max_llm, cfg.max_llm, 8, 5)
    max_rounds = _auto_def(args.max_rounds, cfg.max_rounds, 3, 2)
    # [S2] 자율 모드 스윕 상한은 고정점 완주용으로 넉넉히(의존 체인이 깊어도 성장-정체 시
    # 조기종료가 1차 종료). 비자율은 보수적 기본 유지.
    max_sweeps = _auto_def(args.max_sweeps, cfg.max_sweeps, _FIXED_POINT_CAP, 2)
    max_parallel = _auto_def(args.max_parallel, getattr(cfg, "max_parallel", None), 4, 1)
    max_variants = _auto_def(args.variants, cfg.max_variants, 3, 2)
    time_budget = pick(args.time_budget, cfg.time_budget, 0.0) or 0.0
    max_cost = pick(args.max_cost, cfg.max_cost, 0.0) or 0.0
    llm_kind = pick(args.llm, cfg.llm_backend, "none")
    llm_tier = pick(args.llm_tier, cfg.llm_tier, "standard")
    state_dir = pick(args.state_dir, cfg.state_dir, "state")

    # 1) Scope Guard 구성 + 타겟 바인딩 (플랫폼별 대역강제/호스트명 허용)
    try:
        guard = ScopeGuard.from_cidr_strings(
            ranges, enforce_ranges=profile.enforce_ranges,
            allow_hostname_target=profile.allow_hostname_target)
    except ValueError as e:
        print(ui.mark_err(f"허용 대역(--range / allowed_ranges) 오류: {e}"), file=sys.stderr)
        return 2
    try:
        guard.bind_target(args.target)
    except ScopeViolation as e:
        print(ui.mark_err(str(e)), file=sys.stderr)
        for h in _scope_hint(str(e), args.target, profile.key):
            print("  " + ui.accent2("→ ") + h, file=sys.stderr)
        return 2

    # 2) 공격자 VPN IP 등록 (지정 or 설정 or 자동탐지)
    attacker = pick(args.attacker_ips, cfg.attacker_ips, None) or detect_vpn_ips()
    for ip in attacker:
        try:
            guard.add_attacker_ip(ip)
        except ValueError as e:
            print(ui.mark_warn(f"공격자 IP 무시: {e}"), file=sys.stderr)

    # 3) 환경 프리플라이트
    pf = preflight(required_tool_keys=["nmap"])
    print(pf.render())
    # 포트 스캔 도구(nmap)가 없으면 시작할 수 없다 — 4번 실패한 뒤 '호스트 응답 없음'으로
    # 오해하게 두지 않고, 바로 설치 방법을 알려 준다(테스트처럼 러너를 주입한 경우는 제외)
    if runner is None and not shutil.which("nmap"):
        print(ui.panel("시작할 수 없음 — nmap 이 없습니다", [
            "포트 스캔(첫 단계)에 nmap 이 필요합니다. 대상 문제가 아닙니다.",
            ui.accent2("설치: ") + ui.bold("sudo apt install -y nmap")
            + ui.dim("   (전체 도구: sudo ./scripts/install_tools.sh)"),
            ui.dim("설치 후 같은 명령을 다시 실행하세요. 점검: assassin --doctor"),
        ], style="warn"), file=sys.stderr)
        return 2
    _mode = ("완전수동" if args.manual           # 승인자 선택과 같은 우선순위(manual 이 최우선)
             else "능동적 완전자동(autonomous)" if args.autonomous
             else "완전자동" if args.auto
             else "스마트(범위밖만 확인)")
    _plat = ui.accent2(profile.name) + ui.dim(f"  ({profile.flag_kind}")
    _plat += ui.dim(f" · {args.category})") if (profile.is_jeopardy and args.category) \
        else ui.dim(")")
    print(ui.panel("세션", [
        ui.kv("플랫폼", _plat, 8),
        ui.kv("타겟", ui.accent2(str(guard.bound_target or guard.bound_host)), 8),
        ui.kv("범위", guard.describe(), 8),
        ui.kv("공격자IP", (ui.ok(", ".join(attacker)) if attacker
                        else ui.dim("(없음)")), 8),
        ui.kv("승인", ui.info(_mode), 8),
        ui.kv("플래그", ui.dim("접두 " + (", ".join(flag_prefixes) or "자동") + " · TAG{} 자동인식"), 8),
        *([ui.kv("시간예산", ui.info(f"{time_budget:g}분 (마감 시 남은 단계 생략·상태 저장)"), 8)]
          if time_budget else []),
        *([ui.kv("비용상한", ui.info(f"${max_cost:g} (넘으면 규칙 기반으로 계속)"), 8)]
          if max_cost else []),
    ], style="navy") + "\n")

    # 4) 지식베이스 + 취약점 KB 로드 (사용자 학습데이터로 성장)
    #    실제 실행이면 하루 1회 공유 저장소의 최신 시드를 검증 후 로컬 캐시에 반영
    if runner is None and not args.offline and not args.no_kb_sync:
        from . import kb_sync as _kbs
        try:
            _print_kb_sync(_kbs.auto_sync(knowledge_dir))
        except Exception as e:   # noqa: BLE001 — 지식 동기화 실패가 풀이를 막지 않게
            print(ui.mark_warn(f"공유 시드 동기화 건너뜀: {e}"), file=sys.stderr)
    kb = KnowledgeBase.load(base_dir=knowledge_dir)
    from .vuln import VulnKB
    vuln_kb = VulnKB.load(base_dir=knowledge_dir)
    print(ui.kv("지식베이스", f"규칙 {ui.bold(str(len(kb.rules)))}개 · 노트 "
                f"{ui.bold(str(len(kb.notes)))}개 · 취약점규칙 "
                f"{ui.bold(str(len(vuln_kb.rules)))}개", 10))
    # 조건 없는 참고 규칙(크래킹·RE 등)은 의도된 보존이라 매 실행 화면에서는 숨긴다(진짜 오류만 표시)
    kb_warn = [w for w in kb.warnings if "when 조건 없음" not in w]
    if kb_warn:
        print(ui.mark_warn(f"지식베이스 경고 {len(kb_warn)}건 (예: {kb_warn[0]})"))

    # 5) LLM 두뇌 구성(선택)
    llm_router, llm_status = _build_llm_router(llm_kind, llm_tier, **_ollama_opts(cfg))
    print(ui.kv("LLM", ui.info(llm_status), 10) + "\n")

    # 6) 상태 저장소 (중단/재개) + 자격증명 볼트
    from .creds import Credential, CredentialVault
    from .state import StateStore
    store = None if args.no_save else StateStore(state_dir)
    vault = CredentialVault.from_cli(args.creds)
    if args.cred_file:   # 파일에서 자격증명 일괄 로드(인라인 --cred 와 합쳐짐)
        loaded = CredentialVault.load_file(args.cred_file)
        for c in loaded.creds:
            vault.add(c)
        if not loaded.creds:
            print(ui.mark_warn(f"--cred-file: '{args.cred_file}' 에서 읽은 자격증명 없음(형식·경로 확인)"))
    # 실행 결과 기반 변형 학습(세션 넘어 누적) — <state-dir>/variant_stats.json
    import os as _osvs

    from .variant_stats import VariantStats
    vstats_path = _osvs.path.join(state_dir, "variant_stats.json")
    variant_stats = VariantStats() if args.no_save else VariantStats.load(vstats_path)
    if args.resume and store and store.exists(args.target):
        prior = store.load(args.target)
        if prior:
            print("재개할 저장 상태 발견:\n" + prior.summary() + "\n")
            for d in prior.credentials:   # 저장된 자격증명 재사용
                vault.add(Credential.from_dict(d))
    if vault.creds:
        print(f"자격증명 볼트: {[c.label() for c in vault.creds]}\n")

    # 6.5) 감사 로그
    import os as _os

    from .audit import AuditLog, NullAudit
    audit: NullAudit | AuditLog
    if args.no_audit:
        audit = NullAudit()
    else:
        log_path = args.log_file or _os.path.join(
            state_dir, f"audit_{StateStore._safe(args.target)}.jsonl")
        audit = AuditLog(log_path)
        print(f"감사 로그: {log_path}\n")

    # 6.6) CVE/CWE 자동 수집기(공식 출처, 기본 활성 · 캐시 · 오프라인 안전)
    from .enrich import Enricher
    enrich_cache = args.enrich_cache or _os.path.join(knowledge_dir, "cve_cache")
    enricher = None if args.no_enrich else Enricher(
        cache_dir=enrich_cache, enabled=not args.offline)
    print(ui.kv("CVE수집", (ui.dim("비활성") if args.no_enrich
                else (ui.info("캐시만(오프라인)") if args.offline
                      else ui.ok("자동(NVD/GitHub) · 캐시 " + enrich_cache))), 10) + "\n")

    # 6.7) 자율 지식 획득기 — 모르는 기술을 권위 출처에서 자동 학습(allowlist·P1)
    #      autonomous 기본 활성, --learn-gaps 로 명시 활성, --no-learn-gaps 로 끔.
    # --web-learn 은 '미해석 공백'을 웹에서 배우므로 공백 탐지(learn-gaps)를 함께 켠다
    learn_gaps = ((args.learn_gaps or args.autonomous or args.web_learn)
                  and not args.no_learn_gaps)
    learner = None
    if learn_gaps:
        from .learn import ReferenceLearner
        learner = ReferenceLearner(
            cache_dir=_os.path.join(knowledge_dir, "notes", "learned"),
            enabled=not args.offline)
    print(ui.kv("자율학습", (ui.dim("비활성") if not learn_gaps
                else (ui.info("공백기록만(오프라인)") if args.offline
                      else ui.ok("자동(권위 출처 → KB 즉시 반영)"))), 10) + "\n")

    # 6.8) 인터넷 검색 학습기 — 미해석 공백을 웹에서 학습(HTB 라이트업 가드 항상 ON).
    #      --web-learn 또는 autonomous 기본 활성, --no-web-learn 로 끔. 오프라인이면 생략.
    web_learn = (args.web_learn or args.autonomous) and not args.no_web_learn and not args.offline
    web_learner = None
    if learn_gaps and web_learn:
        from .web_search import WebLearner
        web_learner = WebLearner(
            cache_dir=_os.path.join(knowledge_dir, "notes", "learned"), enabled=True)
    print(ui.kv("웹학습", (ui.dim("비활성") if not (learn_gaps and web_learn)
                else ui.ok("인터넷 검색(HTB 라이트업 차단 · 미해석 공백)")), 10) + "\n")

    # 7) 오케스트레이션 (유한 단계: RECON→PROFILE→ENUM→(LLM)→REPORT)
    # 승인 모드: --auto(완전자동) / --manual(완전수동) / 기본=스마트(범위밖만 확인)
    from .approval import smart_approver
    from .tools.recon import Approver
    approver: Approver
    if args.manual:                               # --manual 은 autonomous 보다 우선(안전)
        approver = interactive_approver
    elif args.auto or args.autonomous:            # autonomous → 범위내 자동승인
        approver = auto_approve_in_scope
    else:
        approver = smart_approver
    from .approval import interactive_observer
    observer = interactive_observer if (args.observe and runner is None) else None

    # 7.5) 실행기 + 작업공간 — 샌드박스(docker)는 egress 방화벽을 건 뒤에만 명령을 받는다
    sandbox_kind = pick(args.sandbox, cfg.sandbox, "none")
    workspace = None
    import typing as _t
    sandbox: _t.Any = None   # DockerSandbox | VMSandbox | None — 공통 수명주기(start/stop)만 사용
    if args.files or sandbox_kind != "none":
        from .state import StateStore as _SS
        from .workspace import Workspace, WorkspaceError
        workspace = Workspace(_os.path.join(state_dir, "work", _SS._safe(args.target)))
        if args.files:
            try:
                added = workspace.import_paths(args.files)
            except (WorkspaceError, OSError) as e:
                print(ui.mark_err(f"첨부파일 가져오기 실패: {e}"), file=sys.stderr)
                return 2
            print(ui.kv("첨부파일", ui.ok(", ".join(added)) + ui.dim(f"  → {workspace.root}"), 10))
    if runner is None and sandbox_kind == "docker":
        from .tools.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxError, allowlist_for
        assert workspace is not None   # sandbox_kind != "none" → 위에서 생성됨
        try:
            cidrs, hosts = allowlist_for(guard)
            sandbox = DockerSandbox(workspace.root, cidrs,
                                    image=args.sandbox_image or DEFAULT_IMAGE,
                                    lports=[args.lport], hosts=hosts)
            sandbox.start()
        except SandboxError as e:
            print(ui.panel("샌드박스 시작 실패 — 실행하지 않습니다", [
                str(e),
                ui.accent2("이미지 빌드: ") + ui.bold("./scripts/build_sandbox.sh"),
                ui.dim("Docker 데몬·권한(docker 그룹) 확인. 샌드박스 없이: --sandbox none"),
            ], style="warn"), file=sys.stderr)
            return 2
        runner = sandbox
        print(ui.kv("샌드박스", ui.ok(f"docker {sandbox.name} · egress 허용 {', '.join(cidrs)}"), 10))
    elif runner is None and sandbox_kind == "shell":
        from .tools.sandbox import ShellRunner
        assert workspace is not None   # sandbox_kind != "none" → 위에서 생성됨
        runner = ShellRunner(workdir=workspace.root)
        print(ui.kv("실행기", ui.warn("로컬 bash — 네트워크 강제 없음(스크립트 자동 실행 안 함)"), 10))
    elif runner is None and sandbox_kind == "vm":
        from .tools.sandbox import SandboxError, VMSandbox, allowlist_for
        assert workspace is not None   # sandbox_kind != "none" → 위에서 생성됨
        vm_ssh = args.vm_ssh or cfg.vm_ssh   # 설정파일로 기본 VM 지정 가능(sandbox=vm)
        if not vm_ssh:
            print(ui.panel("VM 샌드박스 — 접속 정보가 필요합니다", [
                "명령을 실행할 VM 의 SSH 대상을 지정하세요.",
                ui.accent2("예: ") + ui.bold("--sandbox vm --vm-ssh kali@192.168.56.10"),
                ui.dim("키: --vm-ssh-key ~/.ssh/id_ed25519 · 포트: --vm-ssh-port 22"),
                ui.dim("완전자율 동적 실행까지 자동으로 하려면(선택): --vm-confine --vm-sudo"),
            ], style="warn"), file=sys.stderr)
            return 2
        try:
            cidrs, hosts = allowlist_for(guard)
            sandbox = VMSandbox(vm_ssh, workspace.root, cidrs,
                                ssh_key=pick(args.vm_ssh_key, cfg.vm_ssh_key, None),
                                ssh_port=pick(args.vm_ssh_port, cfg.vm_ssh_port, 22),
                                lports=[args.lport],
                                sudo=args.vm_sudo or bool(cfg.vm_sudo),
                                confine=args.vm_confine or bool(cfg.vm_confine), hosts=hosts)
            sandbox.start()
        except SandboxError as e:
            print(ui.panel("VM 샌드박스 시작 실패 — 실행하지 않습니다", [
                str(e),
                ui.dim("점검: VM 이 켜져 있고 `ssh " + str(vm_ssh) + "` 가 비밀번호 없이(키) 되는지, "
                       "VPN/네트워크로 타겟에 닿는지."),
                ui.dim("egress 경계 없이 쓰려면 --vm-confine 을 빼세요(동적 실행은 수동 제안)."),
            ], style="warn"), file=sys.stderr)
            return 2
        runner = sandbox
        state = ("egress 강제 " + ", ".join(cidrs)) if sandbox.contained else "네트워크 강제 없음"
        print(ui.kv("실행기", ui.ok(f"vm {vm_ssh} · {state}"), 10))
    if args.autonomous and not getattr(runner, "contained", False):
        print(ui.mark_warn("완전자율인데 egress 강제 샌드박스가 없음 — 스크립트 작성·동적 실행은 "
                           "수동 제안으로 남습니다(권장: --sandbox docker, 또는 --sandbox vm --vm-confine)"))
    if (args.autonomous or args.auto) and not args.manual and getattr(runner, "contained", False):
        from .tools.recon import auto_approve_contained
        approver = auto_approve_contained
    orchestrator = Orchestrator(guard, runner or SubprocessRunner(), kb, approver,
                                workspace=workspace,
                                auto_poc=args.auto_poc,
                                exploit_exec=args.exploit_exec,
                                poc_commands=args.poc_commands or [],
                                dry_run=args.dry_run,
                                observer=observer,
                                max_enum=max_enum,
                                max_llm=max_llm,
                                recon_max_attempts=max_attempts,
                                max_rounds=max_rounds,
                                max_sweeps=max_sweeps,
                                max_variants=max_variants,
                                llm_router=llm_router, vuln_kb=vuln_kb,
                                vault=vault,   # 항상 전달(수확 자격 수용 — 빈 볼트도 안전)
                                flag_kind=profile.flag_kind,
                                flag_prefixes=flag_prefixes,
                                enricher=enricher,
                                platform_name=profile.name,
                                category=(args.category or ""),
                                revshell_port=args.lport,
                                variant_stats=variant_stats,
                                max_parallel=max_parallel,
                                time_budget=time_budget,
                                max_cost=max_cost,
                                learner=learner, learn_gaps=learn_gaps,
                                web_learner=web_learner,
                                state_store=store, resume=args.resume, audit=audit)
    try:
        report = orchestrator.run()
    finally:
        if sandbox is not None:
            sandbox.stop()
    if not args.no_save:
        variant_stats.save(vstats_path)   # 학습 결과 영속화(다음 실행에 반영)
    print("\n" + report.summary())
    if llm_router is not None and llm_router.calls:
        print("\n" + llm_router.cost_summary())

    # 8) 라이트업 생성(선택)
    if args.writeup is not None:
        from .state import StateStore
        from .writeup import generate_tistory, generate_writeup
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

    # 9) 구조화 결과 내보내기(선택) — JSON(기계판독) / HTML(대시보드)
    if args.json_out is not None or args.html_out is not None:
        try:
            from . import kb_sync as _kbs
            report.knowledge = _kbs.knowledge_summary(knowledge_dir)
        except Exception:   # noqa: BLE001 — 현황 집계 실패가 산출물을 막지 않게
            report.knowledge = {}
        stats = getattr(llm_router, "stats", None)
        if isinstance(stats, dict):
            # 카운트와 차단된 백엔드 이름만(예외 원문은 산출물에 넣지 않음)
            report.llm_routing = {**stats,
                                  "disabled": sorted(getattr(llm_router, "disabled", {}) or {})}
        from . import report_export
        from .state import StateStore
        safe = StateStore._safe(args.target)
        _os.makedirs(state_dir, exist_ok=True)
        if args.json_out is not None:
            jp = (args.json_out if args.json_out != "__auto__"
                  else _os.path.join(state_dir, f"report_{safe}.json"))
            try:
                with open(jp, "w", encoding="utf-8") as f:
                    f.write(report_export.to_json(report))
                print(f"JSON 결과 내보내기: {jp}")
            except OSError as e:
                print(f"⚠️ JSON 내보내기 실패: {e}", file=sys.stderr)
        if args.html_out is not None:
            hp = (args.html_out if args.html_out != "__auto__"
                  else _os.path.join(state_dir, f"report_{safe}.html"))
            try:
                with open(hp, "w", encoding="utf-8") as f:
                    f.write(report_export.to_html(report))
                print(f"HTML 대시보드 내보내기: {hp}")
            except OSError as e:
                print(f"⚠️ HTML 내보내기 실패: {e}", file=sys.stderr)

    if report.status == "interrupted":
        return 130   # Ctrl+C 관례(128+SIGINT) — 상태는 저장됨
    return 0 if report.status == "done" else 1


def _run_update(args, cfg, knowledge_dir) -> int:
    """최신화 원클릭(G3): 공유 시드 동기화 + 권위출처 재학습·승격. --offline 이면 네트워크 생략.
    CVE/CWE 참조는 실행 시 자동 수집·캐시되므로 여기선 KB(시드·규칙)만 최신화한다."""
    import os as _os

    from . import ui
    if args.offline:
        print(ui.dim("--offline — 네트워크 최신화 생략(기존 KB 유지). 오프라인에선 할 일이 없습니다."))
        return 0
    print(ui.heading("최신화 — 공유 시드 동기화 + 권위출처 재학습·승격", "🔄"))
    from . import kb_sync as _kbs
    sres = _kbs.sync(knowledge_dir)
    if sres.error:
        print(ui.mark_warn(f"공유 시드 동기화 실패(건너뜀): {sres.error}"))
    else:
        _print_kb_sync(sres, verbose=True)
    from . import learn
    from . import promote as _promote
    ndir = _os.path.join(knowledge_dir, "notes", "learned")
    lresults = learn.ReferenceLearner(cache_dir=ndir, enabled=True).learn_all()
    n_ok = sum(1 for lr in lresults if lr.refs)
    print(ui.mark_ok(f"권위출처 재학습: {n_ok}/{len(lresults)} 주제 노트 갱신"))
    presults = _promote.promote_all(ndir, ndir)
    changed = sum(int(pr.changed) for pr in presults if not pr.error)
    print(ui.mark_ok(f"시드 승격: {changed}개 갱신"
                     + ("  — 'git diff' 검토 후 커밋·PR 하면 모든 사용자에 전파" if changed else "")))
    print(ui.ok("최신화 완료. (CVE/CWE 참조는 타겟 실행 시 자동 수집·캐시)"))
    return 0 if not any(pr.error for pr in presults) else 2


def _run_stats_share(args, cfg) -> int:
    """실행 학습 통계 공유(G1): 내보내기/병합. 통계는 binary+fragment→succ/att 뿐이라
    명령 전체·타겟·출력이 담기지 않아 공유해도 안전하다. 성장이 사용자 사이에 compounding 되게 한다."""
    import os as _os

    from . import ui
    from .config import pick
    from .variant_stats import VariantStats
    sd = pick(args.state_dir, cfg.state_dir, "state")
    local_path = _os.path.join(sd, "variant_stats.json")
    if args.export_stats is not None:
        vs = VariantStats.load(local_path)
        vs.save(args.export_stats)
        print(ui.mark_ok(f"실행 학습 통계 내보내기: {args.export_stats} "
                         f"({len(vs.stats)}개 변형 · 명령/타겟 미포함)"))
        return 0
    # import: 공유 통계를 로컬에 병합
    incoming = VariantStats.load(args.import_stats)
    if not incoming.stats:
        print(ui.mark_err(f"병합할 통계 없음(형식·경로 확인): {args.import_stats}"), file=sys.stderr)
        return 2
    local = VariantStats.load(local_path)
    n = local.merge(incoming)
    local.save(local_path)
    print(ui.mark_ok(f"실행 학습 통계 병합: {n}개 변형 반영 → {local_path} "
                     "(다음 실행부터 성공률 높은 변형 우선)"))
    return 0


def _dispatch_standalone(args, cfg, knowledge_dir):
    """타겟 없이 실행하는 단독 명령(replay·bench·doctor·learn·promote 등)을 처리.
    처리하면 종료코드(int)를, 해당 없으면 None 을 반환해 main() 이 타겟 실행으로 넘어가게 한다."""
    from . import ui
    from .config import pick

    # 실행 기록 재생(감사 로그 → 단계별 HTML)
    if args.replay:
        from . import replay
        try:
            out, n = replay.replay_file(args.replay)
        except OSError as e:
            print(ui.mark_err(f"재생 실패: {e}"), file=sys.stderr)
            return 2
        print(ui.mark_ok(f"재생 HTML 생성: {out} ({n}단계) — 브라우저로 열어 ←/→/스페이스로 넘겨 보세요"))
        return 0

    # 평가 하네스(오프라인 모의 문제) — 성공률·pass@N·명령 수·시간·비용
    if args.bench:
        return _run_bench(args, cfg, knowledge_dir)

    # 라이브 평가 하네스(실제 서비스·진짜 도구) — 신뢰할 수 있는 발표용 수치
    if args.live_bench:
        return _run_live_bench(args, cfg, knowledge_dir)

    # 빠진 도구 자동 설치(옵트인) — 저장소 공식 스크립트만 실행
    if args.install_missing is not None:
        from . import installer
        cats = (None if args.install_missing == "__all__"
                else [c for c in args.install_missing.split() if c])
        rc, msg = installer.install_missing(cats)
        print(ui.kv("도구 설치", msg, 10))
        return rc

    # 환경 자가진단(스캔 안 함) — 완전 초보자 권장 첫 실행
    if args.list_sessions:
        from .state import StateStore
        sdir = pick(args.state_dir, cfg.state_dir, "state")
        targets = StateStore(sdir).list_targets()
        if targets:
            print(ui.accent2(f"저장된 세션 {len(targets)}개 ({sdir}):"))
            for t in targets:
                print("  " + t)
        else:
            print(ui.dim(f"저장된 세션 없음 ({sdir}) — 실행하면 자동 저장됩니다."))
        return 0

    if args.doctor or args.llm_test:
        from .doctor import run_doctor
        text, ok = run_doctor(llm_test=args.llm_test, **_ollama_opts(cfg))
        print(text)
        return 0 if ok else 2

    # 리버스쉘 페이로드 생성(스캔·실행 안 함)
    if args.revshell:
        from . import revshell
        default_host = (args.attacker_ips[0] if args.attacker_ips
                        else next(iter(detect_vpn_ips()), None))
        try:
            lhost, lport = revshell.parse_target(args.revshell, default_host)
        except ValueError as e:
            print(ui.mark_err(str(e)), file=sys.stderr)
            return 2
        print(revshell.render(lhost, lport))
        return 0

    # AWS/S3 열거 자동 준비(스캔·실행 안 함) — 버킷 후보+점검 생성
    if args.cloud:
        from . import cloud
        print(cloud.render([args.cloud]))
        return 0

    # 권한상승 플레이북 자동 준비(스캔·실행 안 함) — OS별 체크리스트 생성
    if args.privesc:
        from . import privesc
        default_atk = (args.attacker_ips[0] if args.attacker_ips
                       else (detect_vpn_ips() or [""])[0])
        print(privesc.render(args.privesc, default_atk or ""))
        return 0

    # 해시 크래킹 자동 준비(실행 안 함) — 종류 식별 + john/hashcat 명령 생성
    if args.crack:
        from . import crack
        print(crack.render(args.crack))
        return 0

    # 사용자 제공 자료 수집(스캔 안 함) — .md/.txt/.pdf 를 지식베이스 노트로 미리 학습
    if args.ingest is not None:
        import os as _osing

        from . import learn
        kdir = knowledge_dir
        paths = learn.ingest(args.ingest,
                             dest_dir=_osing.path.join(kdir, "notes", "ingested"))
        if paths:
            print(ui.heading(f"자료 수집 완료 — {len(paths)}개 노트", "📥"))
            for p in paths[:50]:
                print("  " + ui.dim(p))
        else:
            print(ui.mark_err(f"수집할 .md/.txt/.pdf 자료 없음: {args.ingest}"), file=sys.stderr)
        return 0 if paths else 2

    # 공유 저장소 최신 시드를 지금 동기화(검증 통과분만 로컬 캐시에)
    if args.kb_sync:
        if args.offline:
            print(ui.mark_err("--offline 에서는 공유 시드 동기화를 하지 않습니다"), file=sys.stderr)
            return 2
        from . import kb_sync as _kbs
        sres = _kbs.sync(knowledge_dir)
        if sres.error:
            print(ui.mark_err(f"공유 시드 동기화 실패: {sres.error}"), file=sys.stderr)
            return 2
        _print_kb_sync(sres, verbose=True)
        return 0

    # 최신화 원클릭(G3): 공유 시드 동기화 + 권위출처 재학습·승격
    if args.update:
        return _run_update(args, cfg, knowledge_dir)

    # 실행 학습 통계 내보내기/병합(G1 성장 공유) — binary+fragment 통계만(안전)
    if args.export_stats is not None or args.import_stats is not None:
        return _run_stats_share(args, cfg)

    # 학습 노트 → 번들 시드 승격(스캔·네트워크 없음). 커밋·PR 로 모든 사용자에게 공유.
    if args.promote is not None:
        import os as _ospr

        from . import promote as _promote
        ndir = _ospr.path.join(knowledge_dir, "notes", "learned")
        key = args.promote.strip().lower()
        presults = (_promote.promote_all(ndir, ndir) if key == "all"
                    else [_promote.promote(key, ndir, ndir)])
        if not presults:
            print(ui.mark_warn("승격할 학습 노트 없음 — 먼저 'assassin --learn all' 실행"),
                  file=sys.stderr)
            return 2
        changed = 0
        for pr in presults:
            if pr.error:
                print(ui.mark_err(f"{pr.topic}: {pr.error}"), file=sys.stderr)
                continue
            head = f"{pr.topic}: 승격 {len(pr.accepted)}건 · 거부 {len(pr.rejected)}건"
            print((ui.mark_ok(head) if pr.changed else ui.dim("  " + head + " (변경 없음)")))
            for title, reason in pr.rejected:
                print(ui.dim(f"     ✗ {title} — {reason}"))
            for title, why in pr.pruned:
                print(ui.dim(f"     − {title} — 시드에서 정리({why})"))
            changed += int(pr.changed)
        if changed:
            print(ui.ok(f"\n시드 {changed}개 갱신 — 'git diff {ndir}/seed-*.md' 로 검토 후 커밋·PR 하면 "
                        "병합 시 모든 사용자에게 반영됩니다."))
        return 0 if not any(pr.error for pr in presults) else 2

    # 권위 출처 자가학습(스캔 안 함) — 지식베이스에 노트 저장(P1 유지)
    if args.learn is not None:
        from . import learn
        key = args.learn.strip().lower()
        if key in ("list", "topics", "?"):
            print(ui.heading("학습 가능 주제(권위 출처)", "📚"))
            print("  " + ", ".join(learn.topics()))
            return 0
        import os as _oslearn
        ref_learner = learn.ReferenceLearner(
            cache_dir=_oslearn.path.join(knowledge_dir, "notes", "learned"),
            enabled=not args.offline)
        if key == "all":   # 전체 주제 일괄 사전 학습(미리 학습)
            lresults = ref_learner.learn_all()
            n_ok = sum(1 for lr in lresults if lr.refs)
            print(ui.heading(f"전체 사전 학습 — {n_ok}/{len(lresults)} 주제 노트 생성", "📚"))
            if not args.offline:
                print(ui.dim("  (라이브 수집: 허용 도메인에서 요약 수집)"))
                failed = [(lr.topic, r.title, r.url) for lr in lresults for r in lr.refs
                          if not r.excerpt]
                if failed:   # 끊긴 링크·차단 출처를 드러냄(주간 워크플로 로그에서 바로 보이게)
                    print(ui.mark_warn(f"수집 실패 출처 {len(failed)}개 — 카탈로그 주소 확인 필요"))
                    for topic, title, url in failed:
                        print(ui.dim(f"     {topic}: {title} — {url}"))
                        if _oslearn.environ.get("GITHUB_ACTIONS") == "true":
                            print(f"::warning title=수집 실패 출처::{topic}: {title} — {url}")
            else:
                print(ui.dim("  (오프라인: 출처 포인터 저장 — 번들 시드 노트가 보강)"))
            return 0 if n_ok else 2
        res = ref_learner.learn(args.learn)
        print(res.summary())
        return 0 if res.refs else 2

    return None


def main(argv: list[str] | None = None, runner=None) -> int:
    """최상위 진입점 — 학습용 도구이므로 Ctrl+C·예기치 못한 오류를 raw 트레이스백 대신
    실행 가능한 한 줄 안내로 바꾼다(전체 추적은 ASSASSIN_DEBUG=1). 타겟 실행은
    중단돼도 상태가 저장돼 --resume 으로 이어진다(품질검수 MED)."""
    import os as _os
    try:
        return _main(argv, runner)
    except KeyboardInterrupt:
        from . import ui
        print("\n" + ui.mark_warn(
            "중단됨 — 타겟 실행은 저장된 지점부터 '--resume' 으로 이어갈 수 있습니다."),
            file=sys.stderr)
        return 130
    except SystemExit:
        raise   # argparse·정상 종료 코드는 그대로 전달
    except Exception as e:   # noqa: BLE001 — 사용자에게는 한 줄, 전체 추적은 디버그 플래그로
        if _os.environ.get("ASSASSIN_DEBUG"):
            raise
        from . import ui
        print(ui.mark_err(f"예기치 못한 오류: {type(e).__name__}: {e}"), file=sys.stderr)
        print(ui.dim("진단은 'assassin --doctor', 전체 추적은 ASSASSIN_DEBUG=1 로 다시 실행하세요."),
              file=sys.stderr)
        return 1


def _main(argv: list[str] | None = None, runner=None) -> int:
    # runner 주입 가능(테스트). 기본은 실제 Kali 용 SubprocessRunner.
    parser = build_parser()
    args = parser.parse_args(argv)
    from . import ui
    from .config import Config, ConfigError, load_config, pick

    # 단독 명령은 하나만, 타겟 없이 — 조합 시 조용히 하나만 실행되던 문제 방지
    standalone = [flag for flag, v in (
        ("--doctor", args.doctor or args.llm_test), ("--setup-llm", args.setup_llm),
        ("--install-missing", args.install_missing is not None),
        ("--revshell", args.revshell), ("--cloud", args.cloud),
        ("--privesc", args.privesc), ("--crack", args.crack), ("--ingest", args.ingest),
        ("--kb-sync", args.kb_sync), ("--promote", args.promote), ("--learn", args.learn),
        ("--list-sessions", args.list_sessions), ("--update", args.update),
        ("--export-stats", args.export_stats), ("--import-stats", args.import_stats),
        ("--bench", args.bench), ("--live-bench", args.live_bench), ("--replay", args.replay))
        if v not in (None, False)]
    if len(standalone) > 1:
        parser.error(f"함께 쓸 수 없는 단독 명령: {' '.join(standalone)}")
    if standalone and args.target:
        parser.error(f"{standalone[0]} 은(는) 타겟 없이 단독으로 실행합니다")

    # LLM 연결 마법사(대화형) — 설정 파일을 읽기 전에(마법사가 기본 설정을 새로 쓴다)
    from . import llm_setup
    if args.setup_llm:
        llm_setup.apply_credentials()
        setup_res = llm_setup.run_setup()
        return 0 if (setup_res.cancelled or setup_res.backend != "none") else 1

    # 저장된 LLM 키를 환경변수로(이미 설정돼 있으면 환경변수 우선). 키는 화면·파일에 남기지 않는다
    llm_setup.apply_credentials()
    cred_warn = llm_setup.read_credentials()[1]
    if cred_warn:
        print(ui.mark_warn(cred_warn), file=sys.stderr)

    # 설정 파일 로드 + 우선순위 해소 (CLI > config > 기본값) — 단독 명령도 같은 설정을 따른다.
    # --config 가 없으면 마법사가 만든 기본 설정(~/.config/assassin/config.json)을 자동으로 읽는다.
    import os as _os
    user_cfg = llm_setup.user_config_path()
    cfg_path = args.config or (user_cfg if _os.path.isfile(user_cfg) else "")
    try:
        cfg = load_config(cfg_path) if cfg_path else Config()
    except ConfigError as e:
        print(ui.mark_err(f"설정 오류({cfg_path}): {e}"), file=sys.stderr)
        return 2
    if cfg_path and not args.config:
        print(ui.dim(f"설정: {cfg_path} (자동 — 다른 설정은 --config, LLM 끄기는 --llm none)"),
              file=sys.stderr)
    for w in cfg.warnings:
        print(ui.mark_warn(f"설정 경고: {w}"), file=sys.stderr)
    knowledge_dir = pick(args.knowledge, cfg.knowledge_dir, None) or _default_knowledge_dir()

    rc = _dispatch_standalone(args, cfg, knowledge_dir)
    if rc is not None:
        return rc
    if not args.target:
        swallowed = [v for v in (args.writeup, args.json_out, args.html_out)
                     if v not in (None, "__auto__")]
        if swallowed:   # 'assassin --html 10.129.1.5' 처럼 타겟이 경로로 읽힌 경우
            parser.error(f"타겟이 없습니다 — '{swallowed[0]}' 가 출력 경로로 읽혔습니다. "
                         "타겟을 맨 앞에 두세요: assassin <타겟> --html")
        # 인자 없이 실행 = '어떻게 쓰지?' — 긴 옵션 목록 대신 시작 안내를 보여 준다
        print(_start_guide(), file=sys.stderr)
        raise SystemExit(2)

    return _run_target(args, cfg, knowledge_dir, runner)


if __name__ == "__main__":
    raise SystemExit(main())
