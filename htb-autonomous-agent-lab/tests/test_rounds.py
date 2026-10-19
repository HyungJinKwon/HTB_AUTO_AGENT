# 실행: htb-agent 디렉토리에서  python3 tests/test_rounds.py
# 반복 피드백 루프: 이전 관측이 다음 LLM 제안에 반영 + 유한 상한 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                      else RunOutput(c, stdout="output-data"))
# KB 최소화: 빈 KB 로 LLM 효과만 관찰
EMPTY_KB = KnowledgeBase(rules=[], notes=[])

# 적응형 FakeProvider: 이전 관측(findings)에 'adminpanel' 명령 결과가 보이면 다른 명령 제안
def adaptive(system, user, tier):
    if "nuclei" in user:            # 라운드3 이상 — 더 제안 안 함(종료 유도)
        return "nuclei -u http://{t}"
    if "gobuster" in user:          # 라운드2: 이전에 gobuster 가 돌았음 → 새 명령
        return "nuclei -u http://{t}"
    return "gobuster dir -u http://{t} -w /tmp/w.txt"   # 라운드1

print("=== 적응형 반복 라운드 ===")
llm = LLMRouter(FakeProvider(adaptive))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=llm, max_rounds=3, is_tool_available=lambda b: True)
rep = orc.run()
cmds = [f.command for f in rep.llm_findings]
check("라운드1 gobuster 실행", any("gobuster" in c for c in cmds))
check("라운드2 적응해 nuclei 제안(새 명령)", any("nuclei" in c for c in cmds))
check("중복 명령 재실행 안 함", len(cmds) == len(set(cmds)))

print("\n=== max_rounds=1 → 단일 단계 1라운드만 ===")
# 단일 단계(enum)로 제한 + max_rounds=1 → round1 gobuster 만, 적응 라운드 없음
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(adaptive)), max_rounds=1,
                   phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
cmds = [f.command for f in rep.llm_findings]
check("1라운드: gobuster만", any("gobuster" in c for c in cmds) and not any("nuclei" in c for c in cmds))

print("\n=== 새 명령 없으면 조기 종료 ===")
# 항상 같은 명령 → 라운드2에서 0건 추가 → 조기 종료(중복 1건만)
same = LLMRouter(FakeProvider("curl -i http://{t}/"))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=same, max_rounds=5, is_tool_available=lambda b: True)
rep = orc.run()
check("동일 제안 반복 시 1건만(조기종료)", len(rep.llm_findings) == 1)

print("\n=== 전역 max_llm 상한(라운드 합산) ===")
multi = LLMRouter(FakeProvider("curl -i http://{t}/a\ncurl -i http://{t}/b\ncurl -i http://{t}/c\ncurl -i http://{t}/d"))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=multi, max_rounds=5, max_llm=2, is_tool_available=lambda b: True)
rep = orc.run()
check("LLM 총 상한 2 준수", len(rep.llm_findings) <= 2)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
