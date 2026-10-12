# 실행: htb-agent 디렉토리에서  python3 tests/test_deadline_pause.py
#
# [T2-e] Deadline pause/resume — LLM 재시도 백오프 '대기' 시간은 시간 예산에서 제외한다.
# 프로바이더가 slept 누적 → 라우터가 보고 → orchestrator._time_up 이 그만큼 마감을 뒤로 민다.
import sys
import urllib.error
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.llm.base import LLMResponse, Tier  # noqa: E402
from htb_agent.llm.ollama_provider import OllamaProvider  # noqa: E402
from htb_agent.llm.router import HybridRouter, LLMRouter  # noqa: E402
from htb_agent.orchestrator import Orchestrator  # noqa: E402
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


print("=== 프로바이더가 재시도 백오프 대기 누적(slept_sec) ===")
p = OllamaProvider()
p._sleep = lambda s: None       # 실제 대기 없이(테스트)
n = {"c": 0}
def flaky(req, model):
    n["c"] += 1
    if n["c"] <= 2:
        raise urllib.error.URLError("refused")
    return LLMResponse("ok", model)
p._once = flaky
r = p.complete("s", "u", Tier.STANDARD)
check("2회 전이성 실패 후 성공", r.text == "ok")
check("slept_sec > 0 (대기 2회 누적)", p.slept_sec > 0)
check("slept_sec 상한 이내(예산 폭주 아님)", p.slept_sec <= (p._backoff_cap + 0.2) * 2)

print("\n=== 성공만 하면 slept 0 ===")
p2 = OllamaProvider()
p2._sleep = lambda s: None
p2._once = lambda req, model: LLMResponse("ok", model)
p2.complete("s", "u")
check("재시도 없으면 slept_sec==0", p2.slept_sec == 0.0)

print("\n=== LLMRouter / HybridRouter 가 slept 보고 ===")
lr = LLMRouter(provider=p)        # p.slept_sec>0
check("LLMRouter.slept_sec = provider.slept_sec", lr.slept_sec == p.slept_sec)
lr2 = LLMRouter(provider=p2)      # 0
hy = HybridRouter(local=lr, strong=lr2)
check("HybridRouter.slept_sec = 합", abs(hy.slept_sec - (p.slept_sec + p2.slept_sec)) < 1e-9)
check("한쪽만 있어도 안전", HybridRouter(local=lr, strong=None).slept_sec == p.slept_sec)

print("\n=== _time_up 이 slept 만큼 마감을 뒤로 민다 ===")
T = "10.129.1.5"
g = ScopeGuard.from_cidr_strings()
g.bind_target(T)
orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="ok")),
                   KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope, quiet=True)
orc._deadline = 100.0
orc.llm_router = SimpleNamespace(slept_sec=0.0)
orc._clock = lambda: 100.0
check("slept 0 · clock==deadline → 마감", orc._time_up() is True)
orc.llm_router = SimpleNamespace(slept_sec=30.0)
check("slept 30 · clock 100 < 130 → 아직 마감 아님", orc._time_up() is False)
orc._clock = lambda: 130.0
check("slept 30 · clock 130 == 130 → 마감", orc._time_up() is True)

print("\n=== 예산 무제한(_deadline None)은 항상 미마감 ===")
orc._deadline = None
check("무제한이면 slept 무관 False", orc._time_up() is False)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
