# 실행: htb-agent 디렉토리에서  python3 tests/test_s5_budget.py
#
# S5-1 — 소비 스테이지 예산 분리: 결정적 소비 스테이지(핑거프린트·버전프로브·익스조회·웹비밀)가
# report.enum_findings 에 쌓이며 max_enum 을 선점해 KB _enum_round 가 영영 안 돌던 HIGH 버그
# 교정을 고정한다. 소비 스테이지 finding 은 budgeted=False → _spent 가 KB 예산에서 제외.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard               # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput   # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope    # noqa: E402
from htb_agent.knowledge import KnowledgeBase              # noqa: E402
from htb_agent.orchestrator import Orchestrator, EnumFinding  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== _spent: budgeted=False·skipped 는 예산에서 제외 ===")
fs = [
    EnumFinding(command="a", ran=True),                       # 계상
    EnumFinding(command="b", ran=True, budgeted=False),       # 소비 스테이지 — 제외
    EnumFinding(command="c", ran=False, skipped=True),        # 미설치 — 제외
    EnumFinding(command="d", ran=True),                       # 계상
]
check("budgeted·비skipped 만 계상(2)", Orchestrator._spent(fs) == 2)

print("\n=== 전체 run(): 소비 스테이지가 KB enum 예산을 굶기지 않음 ===")
T = "10.129.245.100"
VHOST = "connected.htb"
NMAP = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Apache httpd"/></port>
</ports></host></nmaprun>"""
BODY = "<html><title>FreePBX Administration</title><div>FreePBX 16.0.40.7</div></html>"
SS = ("Exploit Title | Path\n FreePBX 16 - Remote Command Execution | php/webapps/52031.php\n")

def fake(cmd: str) -> RunOutput:
    c = cmd or ""
    if c.startswith("nmap"):
        return RunOutput(c, stdout=NMAP)
    if "searchsploit" in c:
        return RunOutput(c, stdout=SS)
    if VHOST in c and ("curl" in c or "http" in c):
        return RunOutput(c, stdout=BODY)
    return RunOutput(c, stdout="output-data")

g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
# max_enum 을 작게(3) 두고 auto_poc 로 소비 스테이지를 활성화 → 과거엔 소비 프로브가 3을
# 선점해 KB enum 이 0건이었다. 이제는 소비 프로브가 budgeted=False 라 KB enum 이 정상 작동.
orc = Orchestrator(g, FakeRunner(fake), KnowledgeBase.load(), auto_approve_in_scope,
                   hosts_map={VHOST: T}, flag_kind="boot2root",
                   is_tool_available=lambda b: True, auto_poc=True,
                   max_enum=3, quiet=True)
rep = orc.run()

consume = [f for f in rep.enum_findings if not f.budgeted]
kb = [f for f in rep.enum_findings if f.budgeted and not f.skipped]
check("소비 스테이지 프로브가 실제로 떴다(budgeted=False 존재)", len(consume) > 0)
check("그럼에도 KB enum(budgeted) 이 굶지 않고 돌았다", len(kb) > 0)
check("KB 예산 계상은 max_enum(3) 이내", Orchestrator._spent(rep.enum_findings) <= 3)
check("소비 프로브는 예산 계상에서 제외됨(비계상 수 > 0)",
      len(consume) > 0 and Orchestrator._spent(rep.enum_findings) < len(
          [f for f in rep.enum_findings if not f.skipped]))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
