# 실행: htb-agent 디렉토리에서  python3 tests/test_tiering.py
import sys
sys.path.insert(0, "src")
from htb_agent.tiering import tier_for, HybridProvider
from htb_agent.llm.base import Tier, LLMProvider, LLMResponse
from htb_agent.llm.fake_provider import FakeProvider

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== tier_for: 단계별 기본 난이도 ===")
check("enum 은 저렴에서 시작", tier_for("enum") == Tier.CHEAP)
check("recon 은 저렴", tier_for("recon") == Tier.CHEAP)
check("access 는 표준에서 시작", tier_for("access") == Tier.STANDARD)
check("privesc 는 표준에서 시작", tier_for("privesc") == Tier.STANDARD)
check("미지 단계는 표준", tier_for("무언가") == Tier.STANDARD)

print("=== tier_for: 막힐수록 올린다(난이도 신호) ===")
check("enum 1라운드 → 표준", tier_for("enum", round_idx=1) == Tier.STANDARD)
check("enum 2라운드 → 강", tier_for("enum", round_idx=2) == Tier.STRONG)
check("privesc 1라운드 → 강", tier_for("privesc", round_idx=1) == Tier.STRONG)
check("상한을 넘지 않음", tier_for("privesc", round_idx=99) == Tier.STRONG)
check("음수 라운드 방어", tier_for("enum", round_idx=-5) == Tier.CHEAP)

print("=== tier_for: floor(사용자 강제 하한) ===")
check("floor=strong 이면 enum 도 강", tier_for("enum", floor=Tier.STRONG) == Tier.STRONG)
check("floor=standard 면 enum 도 표준 이상",
      tier_for("enum", 0, floor=Tier.STANDARD) == Tier.STANDARD)
check("floor 아래로 내려가지 않음",
      tier_for("recon", 0, floor=Tier.STANDARD) == Tier.STANDARD)
check("floor 와 라운드 함께 적용",
      tier_for("enum", round_idx=1, floor=Tier.STANDARD) == Tier.STRONG)


# ── HybridProvider 배선 ──────────────────────────────────────────
def prov(name, text="ok"):
    p = FakeProvider(text)
    p.name = name
    return p

class Boom(LLMProvider):
    name = "boom"
    models = {Tier.CHEAP: "boom"}
    def complete(self, system, user, tier=Tier.STANDARD, max_tokens=1024):
        raise RuntimeError("프로바이더 폭발")


print("=== HybridProvider: 티어별 라우팅 ===")
local, ext = prov("ollama", "L"), prov("claude", "E")
h = HybridProvider(local=local, external=ext)   # external_from=STRONG 기본
check("CHEAP → 로컬", h.complete("s", "u", Tier.CHEAP).text == "L")
check("STANDARD → 로컬", h.complete("s", "u", Tier.STANDARD).text == "L")
check("STRONG → 외부", h.complete("s", "u", Tier.STRONG).text == "E")

# external_from 조정 — STANDARD 부터 외부로
h2 = HybridProvider(local=local, external=ext, external_from=Tier.STANDARD)
check("경계 조정: STANDARD → 외부", h2.complete("s", "u", Tier.STANDARD).text == "E")
check("경계 조정: CHEAP 은 로컬", h2.complete("s", "u", Tier.CHEAP).text == "L")

print("=== HybridProvider: 폴백 ===")
# 외부가 죽으면 로컬로 폴백 (STRONG 요청이어도)
h3 = HybridProvider(local=prov("ollama", "L"), external=Boom())
check("외부 실패 → 로컬 폴백", h3.complete("s", "u", Tier.STRONG).text == "L")
# 로컬이 죽으면 외부로 폴백 (CHEAP 요청이어도)
h4 = HybridProvider(local=Boom(), external=prov("claude", "E"))
check("로컬 실패 → 외부 폴백", h4.complete("s", "u", Tier.CHEAP).text == "E")
# 둘 다 죽으면 명확히 실패
h5 = HybridProvider(local=Boom(), external=Boom())
try:
    h5.complete("s", "u", Tier.CHEAP); ok = False
except RuntimeError: ok = True
check("둘 다 실패 → RuntimeError", ok)

print("=== HybridProvider: 한쪽만 ===")
check("external 없음도 동작", HybridProvider(local=local, external=None)
      .complete("s", "u", Tier.STRONG).text == "L")
check("local 없음도 동작", HybridProvider(local=None, external=ext)
      .complete("s", "u", Tier.CHEAP).text == "E")
try:
    HybridProvider(local=None, external=None); ok = False
except ValueError: ok = True
check("둘 다 None 은 생성 거부", ok)

print("=== HybridProvider: available / 비용 모델명 ===")
check("한쪽이라도 살아있으면 available", HybridProvider(local=local, external=Boom()).available()[0])
# 실제 응답한 프로바이더의 모델명이 실려야 비용 집계가 맞는다
r = HybridProvider(local=prov("ollama"), external=prov("claude")).complete("s", "u", Tier.CHEAP)
check("응답 model 은 로컬 모델명", r.model.startswith("fake"))

print("=== 통합: 라우터 경유 ===")
from htb_agent.llm.router import LLMRouter
def responder(system, user, tier):
    return f"id  # tier={tier.value}"
rp = FakeProvider(responder)
router = LLMRouter(rp, default_tier=Tier.CHEAP)
router.suggest_commands({}, "10.129.1.5", tier=tier_for("privesc", round_idx=1))
check("라우터가 정책 티어를 프로바이더로 전달", router.calls == 1)

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
