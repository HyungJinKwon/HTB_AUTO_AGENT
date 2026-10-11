# 실행: htb-agent 디렉토리에서  python3 tests/test_llm_cost.py
import sys
sys.path.insert(0, "src")
from htb_agent.llm.pricing import estimate_cost
from htb_agent.llm.base import LLMResponse
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 가격 추정 ===")
# Opus 5.5: in $4, out $20 /1M. 1M in + 1M out = 4 + 20 = 24
check("opus 5.5 기본", abs(estimate_cost("claude-opus-5-5", 1_000_000, 1_000_000) - 24.0) < 1e-6)
# Sonnet 5.5: in $2 out $10 → 0.5M in + 0.2M out = 1.0 + 2.0 = 3.0
check("sonnet 5.5", abs(estimate_cost("claude-sonnet-5-5", 500_000, 200_000) - 3.0) < 1e-6)
# 캐시 읽기는 저렴 → 같은 총입력이라도 캐시로 읽으면 비용 감소.
# (input_tokens 는 '비캐시' 입력 수 — 캐시읽기/생성과 서로소. 캐시로 읽은 만큼 비캐시 입력이 줄어듦.
#  과거 테스트는 prompt_tokens 에 총입력을 넣고 캐시를 또 빼는 '이중차감' 버그 의미를 인코딩했었음.)
full = estimate_cost("claude-opus-5-5", 1_000_000, 0)                                # 전량 비캐시 입력
cached = estimate_cost("claude-opus-5-5", 100_000, 0, cache_read_tokens=900_000)     # 90%를 캐시로
check("캐시 읽기로 비용 감소", cached < full)
# 회귀 가드(F2): 캐시 토큰이 비캐시 입력(prompt_tokens)을 0 으로 깎지 않는다(이중차감 금지)
only_uncached = estimate_cost("claude-opus-5-5", 200_000, 0)
with_cache = estimate_cost("claude-opus-5-5", 200_000, 0, cache_read_tokens=5_000_000)
check("비캐시 입력은 캐시량과 무관하게 과금됨(이중차감 없음)", with_cache > only_uncached)
check("미등록 모델(로컬)은 0", estimate_cost("llama3.1:8b", 1_000_000, 1_000_000) == 0.0)
# Haiku 5.5(CHEAP 티어): in $0.10 out $0.50 → 1M in + 1M out = 0.1 + 0.5 = 0.6
check("haiku 5.5 등록됨", abs(estimate_cost("claude-haiku-5-5", 1_000_000, 1_000_000) - 0.6) < 1e-6)

print("\n=== 티어 모델 세대 일관성 ===")
from htb_agent.llm.claude_provider import ClaudeProvider
from htb_agent.llm.base import Tier
from htb_agent.llm.pricing import PRICES
cp = ClaudeProvider()
check("CHEAP = haiku 5.5(현행)", cp.models[Tier.CHEAP] == "claude-haiku-5-5")
check("모든 티어 모델이 가격표에 존재",
      all(cp.models[t] in PRICES for t in (Tier.CHEAP, Tier.STANDARD, Tier.STRONG)))

print("\n=== 라우터 누적 집계 ===")
# usage 가 담긴 LLMResponse 를 반환하는 FakeProvider
def responder(system, user, tier):
    return LLMResponse(text="nmap -sV {t}", model="claude-sonnet-5-5",
                       prompt_tokens=1000, completion_tokens=100,
                       cache_read_tokens=500)
r = LLMRouter(FakeProvider(responder))
r.suggest_commands({}, "10.129.1.5")
r.suggest_commands({}, "10.129.1.5")
check("호출 2회 집계", r.calls == 2)
check("입력 토큰 누적", r.total_prompt == 2000)
check("캐시 읽기 누적", r.total_cache_read == 1000)
check("비용 > 0", r.total_cost > 0)
check("cost_summary 문자열", "추정 비용" in r.cost_summary() and "LLM 호출 2회" in r.cost_summary())

print("\n=== 캐시 미사용 provider(문자열 반환) 안전 ===")
r2 = LLMRouter(FakeProvider("nmap -sV {t}"))
r2.suggest_commands({}, "10.129.1.5")
check("usage 없는 응답도 집계 안전", r2.calls == 1 and r2.total_cost == 0.0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
