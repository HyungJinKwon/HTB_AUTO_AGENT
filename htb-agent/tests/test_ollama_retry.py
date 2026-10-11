# 실행: htb-agent 디렉토리에서  python3 tests/test_ollama_retry.py
#
# Ollama 재시도/백오프 (감사 FINDING: Ollama 는 재시도가 없어 일시 네트워크 블립 1회가
# 하드 오류로 집계 → 서킷브레이커 조기 트립). 전이성 오류만 지터드 지수백오프로 소수 재시도.
# 네트워크 없이 _once/_sleep 주입으로 검증.
import sys
import urllib.error

sys.path.insert(0, "src")
from htb_agent.llm.base import LLMResponse, Tier  # noqa: E402
from htb_agent.llm.ollama_provider import OllamaProvider  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def prov():
    p = OllamaProvider()
    p._sleep = lambda s: None       # 실제 대기 없이
    return p


print("=== 전이성 오류는 재시도로 복구 ===")
p = prov()
n = {"c": 0}
def flaky(req, model):
    n["c"] += 1
    if n["c"] <= 2:                 # 처음 2회 전이성 실패
        raise urllib.error.URLError("connection refused")
    return LLMResponse("ok", model)
p._once = flaky
r = p.complete("s", "u", Tier.STANDARD)
check("2회 전이성 실패 후 성공(재시도 복구)", r.text == "ok")
check("정확히 3회 시도(1+재시도2)", n["c"] == 3)

print("\n=== 재시도 소진 → 마지막 오류 전파(라우터가 폴백/집계) ===")
p2 = prov()
m = {"c": 0}
def always_timeout(req, model):
    m["c"] += 1
    raise TimeoutError("timed out")
p2._once = always_timeout
raised = False
try:
    p2.complete("s", "u")
except TimeoutError:
    raised = True
check("소진 시 예외 전파", raised)
check("총 3회만 시도(무한재시도 아님)", m["c"] == 3)

print("\n=== 4xx 클라이언트 오류는 즉시 실패(재시도 무의미) ===")
p3 = prov()
k = {"c": 0}
def http404(req, model):
    k["c"] += 1
    raise urllib.error.HTTPError("http://x", 404, "not found", None, None)
p3._once = http404
r3 = False
try:
    p3.complete("s", "u")
except urllib.error.HTTPError:
    r3 = True
check("4xx 즉시 전파", r3)
check("4xx 는 재시도 안 함(1회)", k["c"] == 1)

print("\n=== 5xx 서버 오류는 재시도 ===")
p4 = prov()
j = {"c": 0}
def http503(req, model):
    j["c"] += 1
    if j["c"] <= 1:
        raise urllib.error.HTTPError("http://x", 503, "unavail", None, None)
    return LLMResponse("recovered", model)
p4._once = http503
r4 = p4.complete("s", "u")
check("5xx 후 재시도로 복구", r4.text == "recovered" and j["c"] == 2)

print("\n=== 백오프는 상한을 지킨다(예산 보호) ===")
pb = prov()
check("모든 attempt 백오프 ≤ cap+지터", all(pb._backoff(a) <= pb._backoff_cap + 0.2 for a in range(12)))
check("백오프는 증가(초기 몇 단계)", pb._backoff(0) <= pb._backoff(3) + 0.2)


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
