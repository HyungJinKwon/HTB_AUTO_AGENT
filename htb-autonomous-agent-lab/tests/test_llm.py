# 실행: htb-agent 디렉토리에서  python3 tests/test_llm.py
import sys
sys.path.insert(0, "src")
from htb_agent.llm.base import Tier
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 티어 모델 매핑 ===")
p = FakeProvider("x")
check("cheap/standard/strong 모델 상이",
      len({p.model_for(Tier.CHEAP), p.model_for(Tier.STANDARD), p.model_for(Tier.STRONG)}) == 3)

print("\n=== 라우터 파싱(후보 정제) ===")
fake_text = """\
nmap -sV {t}
- gobuster dir -u http://{t} -w /tmp/w.txt
1. whatweb http://{t}
nmap -sV {t}
evil-winrm -i {t} -u {user} -p {pass}
```
# 주석줄
"""
router = LLMRouter(FakeProvider(fake_text), max_items=10)
cmds = router.suggest_commands({"profile": "linux"}, "10.129.1.5")
check("{t} 치환", all("10.129.1.5" in c for c in cmds))
check("번호/불릿 제거", any(c.startswith("whatweb") for c in cmds) and any(c.startswith("gobuster") for c in cmds))
check("중복 제거", cmds.count("nmap -sV 10.129.1.5") == 1)
check("크리덴셜 플레이스홀더 라인 제외", all("evil-winrm" not in c for c in cmds))
check("주석/코드펜스 제외", all(not c.startswith("#") and "```" not in c for c in cmds))

print("\n=== 티어 전달 ===")
seen = {}
def responder(system, user, tier):
    seen["tier"] = tier
    return "nmap -sV {t}"
LLMRouter(FakeProvider(responder)).suggest_commands({}, "10.129.1.5", tier=Tier.STRONG)
check("지정 티어 전달됨", seen.get("tier") == Tier.STRONG)

print("\n=== 오케스트레이터 + LLM (게이트 적용) ===")
LINUX_WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner_responder(cmd):
    if cmd.startswith("nmap"): return RunOutput(cmd, stdout=LINUX_WEB)
    return RunOutput(cmd, stdout="ok-output")
ALL = lambda b: True

# LLM 이 범위내 명령 제안 → 게이트 통과 → 실행
llm = LLMRouter(FakeProvider("ffuf -u http://{t}/FUZZ -w /tmp/w.txt"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm, is_tool_available=ALL)
rep = orc.run()
check("LLM 제안 실행됨", any(f.ran for f in rep.llm_findings))

# LLM 이 범위밖 대상 제안 → 범위 게이트가 차단(자동승인 거부)
llm_bad = LLMRouter(FakeProvider("nmap -sV 8.8.8.8"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm_bad, is_tool_available=ALL)
rep = orc.run()
check("범위밖 LLM 명령 차단(미실행)",
      all(not f.ran for f in rep.llm_findings) and
      any("미승인" in f.note for f in rep.llm_findings))

# max_llm 상한
llm_many = LLMRouter(FakeProvider("curl -i http://{t}/a\ncurl -i http://{t}/b\ncurl -i http://{t}/c"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm_many, max_llm=2, is_tool_available=ALL)
rep = orc.run()
check("LLM 상한 준수(<=2)", len(rep.llm_findings) <= 2)

# LLM 백엔드 예외 → 전체 안 깨짐
class Boom(FakeProvider):
    def complete(self, *a, **k): raise RuntimeError("boom")
orc = Orchestrator(guard(), FakeRunner(runner_responder), KnowledgeBase.load(),
                   auto_approve_in_scope, llm_router=LLMRouter(Boom("x")), is_tool_available=ALL)
rep = orc.run()
check("LLM 오류 시 graceful", rep.status == "done" and any("LLM 제안 실패" in s for s in rep.manual_suggestions))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
