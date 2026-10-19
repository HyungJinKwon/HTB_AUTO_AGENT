# 실행: htb-agent 디렉토리에서  python3 tests/test_phases.py
# 모의해킹 단계가 '순서대로'(enum→access→…) 진행·태깅되는지 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.creds import CredentialVault
from htb_agent.orchestrator import Orchestrator, PENTEST_PHASES

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="winrm"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.10"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=AD) if c.startswith("nmap")
                      else RunOutput(c, stdout="ok"))
ALL = lambda b: True

print("=== 단계 순서 정의 ===")
check("순서: enum→access→privesc→lateral",
      [k for k, _ in PENTEST_PHASES] == ["enum", "access", "privesc", "lateral"])

print("\n=== enum 단계 태깅 ===")
rep = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                   is_tool_available=ALL).run()
check("enum 실행 결과 존재", any(f.ran for f in rep.enum_findings))
check("enum 결과는 phase=enum", all(f.phase == "enum" for f in rep.enum_findings))
check("요약에 '열거' 단계 섹션", "단계: 열거" in rep.summary())

print("\n=== 크리덴셜 확보 시 access 단계 진행(순서대로) ===")
v = CredentialVault.from_cli(["administrator:Passw0rd"])
rep = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                   vault=v, is_tool_available=ALL).run()
access_runs = [f for f in rep.enum_findings if f.phase == "access" and f.ran]
check("access 단계 실행됨(evil-winrm 승격)",
      any("evil-winrm" in f.command for f in access_runs))
check("access 명령 phase=access 태깅", all(f.phase == "access" for f in access_runs))
# 순서: enum 결과가 access 결과보다 먼저 기록
phases_in_order = [f.phase for f in rep.enum_findings]
first_access = phases_in_order.index("access") if "access" in phases_in_order else 10**9
last_enum = max((i for i, p in enumerate(phases_in_order) if p == "enum"), default=-1)
check("enum 이 access 보다 먼저 진행", last_enum < first_access)
check("진행단계 메시지에 enum→access", "enum→access" in rep.message)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
