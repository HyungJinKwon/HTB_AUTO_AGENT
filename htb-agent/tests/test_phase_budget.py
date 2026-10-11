# 실행: htb-agent 디렉토리에서  python3 tests/test_phase_budget.py
#
# [S5-1b] 단계별 공정배분(per-phase budget): max_enum/max_llm 은 '단계마다 독립 예산'이다.
# 과거엔 _spent 가 전역합산이라, 순서상 먼저 도는 enum 이 max_enum 을 독식하면 access/
# privesc/lateral 의 KB 열거 예산이 0 으로 굶었다(boot2root 에서 privesc/lateral 열거가
# 핵심인데 치명적). 이 테스트는 (1) _spent(phase=…) 필터와 (2) 전체 run() 에서 뒤 단계가
# 굶지 않음을 고정한다.
import sys

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase, Rule  # noqa: E402
from htb_agent.orchestrator import EnumFinding, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


print("=== _spent(phase=…): 단계별로만 계상 ===")
fs = [
    EnumFinding(command="a", phase="enum", ran=True),
    EnumFinding(command="b", phase="enum", ran=True),
    EnumFinding(command="c", phase="access", ran=True),
    EnumFinding(command="d", phase="access", ran=True, budgeted=False),  # 소비 — 제외
    EnumFinding(command="e", phase="access", ran=False, skipped=True),   # 미설치 — 제외
    EnumFinding(command="f", phase="privesc", ran=True),
]
check("enum 단계 계상(2)", Orchestrator._spent(fs, 0, "enum") == 2)
check("access 단계 계상(1, 소비·미설치 제외)", Orchestrator._spent(fs, 0, "access") == 1)
check("privesc 단계 계상(1)", Orchestrator._spent(fs, 0, "privesc") == 1)
check("전역(phase=None)은 합산(4) — 하위호환", Orchestrator._spent(fs) == 4)
check("base 오프셋 존중", Orchestrator._spent(fs, 2, "access") == 1)

print("\n=== 전체 run(): 먼저 도는 enum 이 max_enum 을 다 써도 access 가 굶지 않음 ===")
T = "10.129.1.5"
# enum·access 두 단계 모두 '실행 가능한' 명령을 넉넉히(각 5개) 가진 KB.
# max_enum=2 → 과거(전역예산): enum 이 2를 쓰면 access 는 0. 지금(단계별): 각 2.
kb = KnowledgeBase(rules=[
    Rule("enum_web", [f"curl -s http://{{t}}/e{i}" for i in range(5)],
         ports=[80], services=["http"], tags=["web"], phase="enum"),
    Rule("access_web", [f"curl -s http://{{t}}/a{i}" for i in range(5)],
         ports=[80], services=["http"], tags=["web"], phase="access"),
], notes=[])

NMAP = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>"""

def fake(cmd: str) -> RunOutput:
    c = cmd or ""
    if c.startswith("nmap"):
        return RunOutput(c, stdout=NMAP)
    return RunOutput(c, stdout="ok")

g = ScopeGuard.from_cidr_strings()
g.bind_target(T)
orc = Orchestrator(g, FakeRunner(fake), kb, auto_approve_in_scope,
                   is_tool_available=lambda b: True, max_variants=1,
                   max_enum=2, max_rounds=1, max_sweeps=1, quiet=True)
rep = orc.run()

enum_spent = Orchestrator._spent(rep.enum_findings, 0, "enum")
access_spent = Orchestrator._spent(rep.enum_findings, 0, "access")
check("enum 단계가 예산(2)을 썼다", enum_spent == 2)
check("access 단계도 독립 예산(2)을 받아 굶지 않았다", access_spent == 2)
check("각 단계 ≤ max_enum(2) — 단계별 상한 준수",
      enum_spent <= 2 and access_spent <= 2)
check("전역 합산은 단계별 예산의 합(4) — 전역상한 아님", enum_spent + access_spent == 4)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
