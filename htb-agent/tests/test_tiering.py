# 실행: htb-agent 디렉토리에서  python3 tests/test_tiering.py
#
# tiering.py (해커톤 lab 에서 선별 이식) — 라운드 기반 티어 상승(tier_for) + 모델별 프롬프트
# 예산(profile_for/ModelProfile). phase 기본값은 루트 tier_for_phase 를 따라 회귀 없음.
import sys

sys.path.insert(0, "src")

from htb_agent.llm.base import Tier                          # noqa: E402
from htb_agent.llm.tiering import ModelProfile, profile_for, tier_for  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== tier_for — phase 기본값(루트 유지) ===")
check("enum 0라운드 = CHEAP", tier_for("enum", 0) == Tier.CHEAP)
check("access 0라운드 = STANDARD", tier_for("access", 0) == Tier.STANDARD)
check("privesc 0라운드 = STRONG(회귀 없음)", tier_for("privesc", 0) == Tier.STRONG)
check("lateral 0라운드 = STRONG", tier_for("lateral", 0) == Tier.STRONG)
check("미상 단계 = STANDARD", tier_for("weird", 0) == Tier.STANDARD)

print("\n=== tier_for — 라운드 거듭될수록 상승 ===")
check("enum 1라운드 → STANDARD", tier_for("enum", 1) == Tier.STANDARD)
check("enum 2라운드 → STRONG", tier_for("enum", 2) == Tier.STRONG)
check("enum 5라운드 → STRONG(상한)", tier_for("enum", 5) == Tier.STRONG)
check("access 1라운드 → STRONG", tier_for("access", 1) == Tier.STRONG)
check("privesc 라운드 올려도 STRONG 유지", tier_for("privesc", 3) == Tier.STRONG)

print("\n=== tier_for — floor(--llm-tier 강제) ===")
check("floor=STRONG 이면 enum 0도 STRONG", tier_for("enum", 0, floor=Tier.STRONG) == Tier.STRONG)
check("floor=STANDARD 이면 enum 0은 STANDARD", tier_for("enum", 0, floor=Tier.STANDARD) == Tier.STANDARD)

print("\n=== profile_for — 모델별 능력 등급·예산 ===")
check("opus → high", profile_for("claude-opus-5-5").klass == "high")
check("haiku → low", profile_for("claude-haiku-5-5").klass == "low")
check("sonnet → mid", profile_for("claude-sonnet-5-5").klass == "mid")
check("high target=4000", profile_for("claude-opus-5-5").target == 4000)
check("반환형 ModelProfile", isinstance(profile_for("claude-opus-5-5"), ModelProfile))

print("\n=== profile_for — 로컬 모델(파라미터 수·창) ===")
check("로컬 7B → low", profile_for("qwen2.5:7b").klass == "low")
check("로컬 32B → mid(소넷급)", profile_for("qwen2.5:32b").klass == "mid")
check("MoE 8x7b → mid(≈56B)", profile_for("mixtral:8x7b").klass == "mid")
p = profile_for("qwen2.5:7b", num_ctx=4096)
check("작은 창이면 ceiling ≤ 창의 60%", p.ceiling <= int(4096 * 0.6))
check("작은 창이면 target ≤ 창의 35%", p.target <= int(4096 * 0.35))
check("사고형(reasoning) max_out 상향", profile_for("deepseek-r1:7b").max_out >= 4096)
check("scale = target/4000", abs(profile_for("claude-opus-5-5").scale - 1.0) < 1e-9)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
