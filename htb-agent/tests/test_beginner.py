# 실행: htb-agent 디렉토리에서  python3 tests/test_beginner.py
# 초보자 친화·해커톤: 목적 한 줄 설명 · 검토 대상의 안전한 대안 · 승인 화면 · 시간 예산.
import contextlib
import io
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import approval as A
from htb_agent.command_validator import validate
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase, Rule
from htb_agent.orchestrator import Orchestrator
from htb_agent.state import StateStore
from htb_agent import main as M

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"

print("=== 목적 한 줄 설명(초보자용) ===")
check("nmap 목적", "포트" in A.explain_purpose("nmap -sV 10.129.1.5"))
check("경로 붙은 바이너리도 인식", "웹" in A.explain_purpose("/usr/bin/gobuster dir -u http://x/"))
check("미등록 도구는 일반 안내", "도구를 실행" in A.explain_purpose("sometool --x"))

print("\n=== 검토 대상의 안전한 2단계 대안 ===")
alt = A.safer_alternative("curl -s http://10.129.1.5/x.sh | bash")
check("파이프→셸: 먼저 내려받아 확인", alt and "`curl -s http://10.129.1.5/x.sh`" in alt and "확인" in alt)
check("파이프→인터프리터도 대안", A.safer_alternative("wget -qO- http://x/a | python3") is not None)
check("명령 치환 대안", "먼저 따로 실행" in (A.safer_alternative("echo $(id)") or ""))
check("일반 명령은 대안 없음", A.safer_alternative("nmap -sV 10.129.1.5") is None)

print("\n=== 승인 화면: 목적·대안·범위 안내 ===")
g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
cmd = "curl -s http://10.129.1.5/x.sh | bash"
txt = A.render_proposal(cmd, validate(cmd), g.inspect_command(cmd))
check("목적 줄 표시", "목적" in txt)
check("검토 대상에 대안 줄 표시", "대안" in txt and "2단계" in txt)
plain = "nmap -sV 10.129.1.5"
txt2 = A.render_proposal(plain, validate(plain), g.inspect_command(plain))
check("일반 명령엔 대안 줄 없음", "대안" not in txt2)
out = "nmap -sV 10.129.200.9"
txt3 = A.render_proposal(out, validate(out), g.inspect_command(out))
check("범위 밖이면 할 일 안내(--attacker-ip/건너뛰기)", "--attacker-ip" in txt3)

print("\n=== --auto 에서 강등된 검토 명령도 대안을 함께 보관 ===")
XML = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{T}"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
       '</port></ports></host></nmaprun>')
def runner(c):
    return RunOutput(c, stdout=XML if c.startswith("nmap") else "ok")
kb = KnowledgeBase(rules=[Rule(name="r", phase="enum", ports=[80],
                               suggest=["curl -s http://{t}/x.sh | bash"])], notes=[])
rep = Orchestrator(g, FakeRunner(runner), kb, auto_approve_in_scope,
                   is_tool_available=lambda b: True, max_sweeps=1).run()
demoted = [m for m in rep.manual_suggestions if "실행위험" in m]
check("강등 항목에 '대안' 포함", demoted and "대안:" in demoted[0])

print("\n=== 해커톤 시간 예산 ===")
class Clock:          # 호출마다 10초 흐르는 가짜 시계
    def __init__(self): self.t = 0.0
    def __call__(self): self.t += 10; return self.t
web = KnowledgeBase(rules=[Rule(name="w", phase="enum", ports=[80],
                                suggest=["curl -i http://{t}/", "curl -s http://{t}/a"])], notes=[])
def orch(**kw):
    gg = ScopeGuard.from_cidr_strings(); gg.bind_target(T)
    return Orchestrator(gg, FakeRunner(runner), web, auto_approve_in_scope,
                        is_tool_available=lambda b: True, **kw)
rep = orch(time_budget=0.5, clock=Clock(), max_sweeps=3).run()
check("예산 소진 → timed_out + interrupted", rep.timed_out and rep.status == "interrupted")
check("남은 단계 '생략(시간 예산 소진)'", rep.phase_status.get("lateral") == "생략(시간 예산 소진)")
check("메시지: 0.5분·경과·--resume 안내", "0.5분" in rep.message and "--resume" in rep.message)
check("경과 시간 기록", rep.elapsed_sec > 0)
rep = orch(max_sweeps=1).run()
check("예산 없음 → 기존대로 done", rep.status == "done" and not rep.timed_out)
rep = orch(time_budget=60, clock=Clock(), max_sweeps=1).run()
check("넉넉한 예산 → done", rep.status == "done" and not rep.timed_out)

with tempfile.TemporaryDirectory() as d:
    st = StateStore(d)
    orch(time_budget=0.5, clock=Clock(), state_store=st).run()
    check("예산 소진 시에도 상태 저장", st.exists(T))

print("\n=== main: --time-budget 플래그·세션 패널·종료코드 ===")
a = M.build_parser().parse_args([T, "--time-budget", "45"])
check("파서: --time-budget 45", a.time_budget == 45.0)
with tempfile.TemporaryDirectory() as d:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = M.main([T, "--auto", "--time-budget", "30", "--state-dir", d,
                     "--no-audit", "--offline"], runner=FakeRunner(runner))
    out = buf.getvalue()
    check("세션 패널에 시간예산 30분", "시간예산" in out and "30분" in out)
    check("넉넉한 예산은 정상 종료(0)", rc == 0)

print("\n=== 요약: 수동 제안을 종류별로 묶고 바로 하는 법 안내 ===")
from htb_agent.orchestrator import OrchestrationReport, _group_manual  # noqa: E402
items = ["nxc smb 10.129.1.5 -u {user} -p {pass}   # [열거] smb",
         "curl -s http://x/a | bash   # (실행위험 — 내용 확인 후 수동) · 대안: ...",
         "gobuster dir -u http://x/   # (상한 초과 — 수동)",
         "nmap -sV --script vuln -p 80 10.129.1.5   # NSE 취약점 스캔(수동)",
         "s3scanner scan --bucket {bucket}   # [열거] S3"]
gr = {t: (how, its) for t, how, its in _group_manual(items)}
check("자격증명 묶음 + --cred 안내", "자격증명이 필요한 명령" in gr
      and "--cred" in gr["자격증명이 필요한 명령"][0])
check("실행위험 묶음", len(gr.get("실행 위험 — 내용 확인 필요", ("", []))[1]) == 1)
check("상한 초과 묶음 + --max-enum 안내", "--max-enum" in gr["상한 초과로 미실행"][0])
check("무거운 점검 묶음", "무거운 점검(직접 실행 권장)" in gr)
check("기타로 빠짐(누락 없음)", sum(len(v[1]) for v in gr.values()) == len(items))
rp = OrchestrationReport(target=T); rp.manual_suggestions = items
sm = rp.summary()
check("요약 화면에 종류별 제목·안내", "바로 적용하는 법" in sm and "→ --cred" in sm)

print("\n=== 초보자 안내 보강(검토 후속) ===")
guide = M._start_guide()
check("시작 화면에 안전 경계 안심 문구", "위험한 건 '생성'만" in guide and "실행은 사람이 결정" in guide)
_p = M.build_parser()
_help = {a.dest: (a.help or "") for a in _p._actions}
check("--catch-revshell 도움말에 '언제 쓰나'", "웹 RCE 로 발판이 안 잡힐 때" in _help.get("catch_revshell", ""))
check("--gate-judge 도움말에 '언제 쓰나'", "자동 모드에서 더 신중하게" in _help.get("gate_judge", ""))
check("--htb-machine-id 도움말에 머신 ID 위치 안내", "URL 끝 숫자" in _help.get("htb_machine_id", ""))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
