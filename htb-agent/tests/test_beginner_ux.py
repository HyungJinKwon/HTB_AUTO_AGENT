# 실행: htb-agent 디렉토리에서  python3 tests/test_beginner_ux.py
# 초보자 화면: 시작 안내 · 그룹별 도움말 · 범위 오류 힌트 · nmap 미설치 조기 안내 · 정찰 오안내 방지 ·
# 박스 줄바꿈 · 수동 제안 축약 · 다음 선택지 묶음 · 끝의 '한눈에 보기'.
import contextlib
import io
import sys

sys.path.insert(0, "src")
from htb_agent import main as M
from htb_agent import recommend as RC
from htb_agent import ui
from htb_agent.orchestrator import OrchestrationReport, _compact_manual
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import ReconExecutor, auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def run(argv, runner=None):
    out, err, code = io.StringIO(), io.StringIO(), None
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = M.main(argv, runner=runner)
    except SystemExit as e:
        code = e.code
    return code, out.getvalue(), err.getvalue()

print("=== 인자 없이 실행 → 시작 안내(긴 옵션 목록 대신) ===")
code, _, err = run([])
check("종료코드 2", code == 2)
check("3단계 안내(doctor·setup-llm·타겟)", "assassin --doctor" in err and "--setup-llm" in err
      and "assassin 10.129.x.x" in err)
check("옵션 목록 벽 없음", "--max-parallel" not in err and "usage:" not in err)

print("\n=== 도움말: 2단 구성(기본=핵심만, --help-all=전체) ===")
h = M.build_parser().format_help()
check("짧은 사용법", h.startswith("usage: assassin <타겟> [옵션]"))
# 기본 -h: 옵션이 보이는 초보자 핵심 그룹 헤딩만 뜬다
for g in ("시작하기", "대상 · 플랫폼", "실행 방식", "LLM 두뇌", "결과물 · 기록"):
    check(f"기본 그룹: {g}", g in h)
check("시작하기가 맨 앞", h.index("시작하기") < h.index("대상 · 플랫폼"))
check("핵심 플래그 노출(--full-auto)", "--full-auto" in h)
check("--help-all 안내", "--help-all" in h)
check("기본엔 고급 옵션 숨김(--max-parallel·--sandbox 벽 제거)",
      "--max-parallel" not in h and "--sandbox" not in h)
check("예시(epilog)", "처음 사용하는 순서" in h and "--full-auto" in h)

# --help-all: 고급 포함 '모든' 그룹·옵션
hf = M.build_parser(full=True).format_help()
for g in ("시간 · 한도", "단독 도구", "지식 · 학습 · 수집"):
    check(f"--help-all 그룹: {g}", g in hf)
check("--help-all 에 고급 옵션 전체", "--max-parallel" in hf and "--sandbox" in hf)

print("\n=== 오타 옵션 → 가장 가까운 실제 옵션 제안(초보자) ===")
_, _, err_typo = run(["10.129.1.5", "--prt"])
check("오타 옵션에 '혹시' 제안", "혹시" in err_typo and "--help" in err_typo)
_, _, err_far = run(["10.129.1.5", "--zzzzzzzz"])
check("전혀 다른 오타엔 과한 제안 안 함", "혹시" not in err_far)
check("도움말 문구 한국어(영문 기본값 아님)",
      "show this help" not in h and "자주 쓰는 옵션" in h)
check("읽기 쉬운 자리표시(cred·attacker-ip)",
      "--cred USER:PASS" in h and "--attacker-ip IP" in h)

print("\n=== 범위 오류 → 바로 고칠 수 있는 힌트(범위 판단은 그대로) ===")
code, _, err = run(["8.8.8.8", "--no-save", "--no-audit", "--offline"])
check("범위 밖 거부 유지(2)", code == 2 and "밖입니다" in err)
check("권한 안내 + HTB Target IP 안내", "권한이 확인된 대상만" in err and "Target IP" in err)
check("대상 IP 를 넣은 우회 명령은 만들지 않음", "assassin 8.8.8.8 --platform" not in err)
code, _, err = run(["box.example", "--no-save", "--no-audit", "--offline"])
check("호스트명 → --platform ctf 안내", code == 2 and "assassin box.example --platform ctf" in err)

print("\n=== nmap 없음 → 4번 실패 대신 바로 설치 안내(실제 러너일 때만) ===")
_orig = M.shutil.which
M.shutil.which = lambda b: None
code, out, err = run(["10.129.1.5", "--no-save", "--no-audit", "--offline"])
M.shutil.which = _orig
check("종료코드 2 + 설치 명령", code == 2 and "sudo apt install -y nmap" in err)
check("'대상 문제 아님' 명시", "대상 문제가 아닙니다" in err)
check("정찰 시도 안 함", "RECON" not in out)

print("\n=== 정찰: 한 번도 실행 못 하면 '호스트 응답 없음'이라 하지 않음 ===")
g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5")
rr = ReconExecutor(g, FakeRunner(lambda c: RunOutput(c, error="'nmap' 미설치", returncode=-1)),
                   auto_approve_in_scope).run_portscan()
check("도구/환경 문제로 안내", rr.status == "escalate" and "도구/실행 환경 문제" in rr.message
      and "응답 없음" not in rr.message)
rr2 = ReconExecutor(g, FakeRunner(lambda c: RunOutput(c, stdout='<?xml version="1.0"?><nmaprun>'
                   '<host><status state="down"/><address addr="10.129.1.5"/></host></nmaprun>')),
                    auto_approve_in_scope).run_portscan()
check("실제로 응답 없으면 기존 문구 유지", "호스트 응답 없음" in rr2.message)

print("\n=== 박스: 여러 줄 항목도 정렬 유지 ===")
pnl = ui.panel("t", ["한 줄", "첫째\n    둘째"])
widths = {ui.display_width(ln) for ln in ui.strip_ansi(pnl).splitlines()} if hasattr(ui, "strip_ansi") \
    else {ui.display_width(ln) for ln in pnl.splitlines()}
check("모든 줄 폭 동일", len(widths) == 1)

print("\n=== 수동 제안: 꼬리표 제거 · 옵션 변형 숨김 ===")
items = ["curl -s http://x/a   # (상한 초과 — 수동)", "curl -s http://x/a -L   # (상한 초과 — 수동)",
         "gobuster dir -u http://x -w w.txt   # (상한 초과 — 수동)",
         "gobuster dir -u http://x -w w.txt -t 50   # (상한 초과 — 수동)", "smbclient -L //x/ -N"]
c = _compact_manual(items)
check("변형 숨김 + 꼬리표 제거", c == ["curl -s http://x/a", "gobuster dir -u http://x -w w.txt",
                               "smbclient -L //x/ -N"])
rp = OrchestrationReport(target="10.129.1.5")
rp.manual_suggestions = [f"tool{i} 10.129.1.5   # (상한 초과 — 수동)" for i in range(12)]
sm = rp.summary(verbose=True)
check("묶음당 6개만 + '외 N개' 안내", "tool5" in sm and "tool6 " not in sm and "외 6개" in sm)

print("\n=== 다음 선택지: 같은 문구 반복 대신 종류별 한 줄 ===")
class R:
    blockers = []; phase_status = {}; enum_findings = []; llm_findings = []
    manual_suggestions = [f"cmd{i} x   # (상한 초과 — 수동)" for i in range(9)] + \
        ["nxc smb x -u {user} -p {pass}"]
s = RC.propose(R())
titles = [i.title for i in s.items]
check("상한 초과 묶음 1개", sum("못 돌린 명령 9개" in t for t in titles) == 1)
check("자격증명 묶음 1개", sum("자격증명이 필요한 명령 1개" in t for t in titles) == 1)
check("'대기 중 수동 제안' 반복 없음", not any("대기 중 수동 제안" in t for t in titles))
check("--resume 안내", any("--resume" in i.rationale for i in s.items))

print("\n=== 끝의 '한눈에 보기' ===")
XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/><ports>'
       '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
       '<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>'
       '</ports></host></nmaprun>')
code, out, _ = run(["10.129.1.5", "--auto", "--no-save", "--no-audit", "--offline"],
                   runner=FakeRunner(lambda c: RunOutput(c, stdout=XML if c.startswith("nmap") else "ok")))
plain = out
check("마지막 박스가 한눈에 보기", "한눈에 보기" in plain[-1500:])
check("결과·서비스·실행·다음에 할 일", all(k in plain[-1500:] for k in ("결과", "80/http", "실행 ", "다음에 할 일")))
rp2 = OrchestrationReport(target="10.129.1.5", status="escalate")
from htb_agent.tools.recon import AttemptRecord, ReconReport  # noqa: E402
rp2.recon = ReconReport(target="10.129.1.5", status="escalate",
                        attempts=[AttemptRecord("a", "nmap", ran=False)])
check("스캔 실패 → doctor·nmap 설치 안내", "nmap 없으면" in rp2.glance())
rp2.recon.attempts[0].ran = True
check("응답 없음 → Spawn·VPN 확인 안내", "Spawn" in rp2.glance() and "openvpn" in rp2.glance())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
