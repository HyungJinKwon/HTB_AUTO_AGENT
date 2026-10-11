# 실행: htb-agent 디렉토리에서  python3 tests/test_audit_fixes_llm.py
#
# 감사에서 확인된 LLM 계층 실버그 2건의 회귀 가드:
#   F1 [HIGH] HybridRouter 서킷브레이커가 백엔드를 '영구' 차단(재활성 경로 없음) →
#             일시 장애(529/타임아웃 2연속)가 세션 전체 능력상실로 굳음. → 반개방(쿨다운 후 재탐색).
#   F3 [MED]  403/404 를 '기대한' 가설이 target_rejected 로 강제 miss → 오탐 stuck/freeze.
import sys

sys.path.insert(0, "src")
from htb_agent.hypotheses import HypothesisLedger  # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider  # noqa: E402
from htb_agent.llm.router import HybridRouter, LLMRouter  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


# ── F1: 반개방 서킷브레이커 ──────────────────────────────────────────────
class Flake(FakeProvider):
    """complete 가 처음 fail_first 번은 예외, 그 뒤엔 정상 응답(일시 장애 모사)."""
    def __init__(self, text, fail_first):
        super().__init__(text)
        self.n = 0
        self.fail_first = fail_first

    def complete(self, *a, **k):
        self.n += 1
        if self.n <= self.fail_first:
            raise RuntimeError("transient 529 overload")
        return super().complete(*a, **k)


print("=== F1: 서킷브레이커 반개방(일시 장애 후 복구) ===")
strong = LLMRouter(Flake("strong-analysis", fail_first=2))   # 처음 2콜 실패 후 복구
local = LLMRouter(FakeProvider("local-analysis"))
hr = HybridRouter(local=local, strong=strong, max_consecutive_errors=2)

hr.analyze({}, "t")                      # strong 콜1 실패 → local 폴백
hr.analyze({}, "t")                      # strong 콜2 실패 → _errors=2 → 차단 + 쿨다운=3
check("2연속 실패 후 strong 차단됨", "strong" in hr.disabled)

for _ in range(3):                       # 쿨다운 3회 소비(strong 건너뜀, local 서빙)
    out_cd = hr.analyze({}, "t")
check("쿨다운 중엔 차단 유지", "strong" in hr.disabled)
check("쿨다운 중 local 로 계속 서빙", out_cd == "local-analysis")

out = hr.analyze({}, "t")                # 쿨다운 경과 → 재탐색: 이제 strong 복구됨
check("쿨다운 경과 후 재탐색 성공 → 차단 해제", "strong" not in hr.disabled)
check("복구된 strong 응답을 다시 사용", out == "strong-analysis")

# 음성: 영구 실패 백엔드는 재탐색해도 다시 차단(복구 아님을 구분)
dead = HybridRouter(local=LLMRouter(FakeProvider("L")),
                    strong=LLMRouter(Flake("S", fail_first=999)), max_consecutive_errors=2)
for _ in range(8):
    dead.analyze({}, "t")
check("영구 실패 strong 은 재탐색 후에도 차단 유지", "strong" in dead.disabled)


# ── F3: 기대한 거부(403/404)는 hit, 기대 안 한 거부는 miss ────────────────
print("\n=== F3: 기대한 거부 신호는 hit(강제 miss 금지) ===")
def ledger_with(expected):
    L = HypothesisLedger()
    L.apply_update({"hypotheses": [{"id": "H1", "text": "엔드포인트 인증 필요 확인",
                                    "expected": expected}]})
    return L

L1 = ledger_with("returns 403 Forbidden")
r1 = L1.record("H1", "curl -i https://t/admin", "HTTP/1.1 403 Forbidden", ran=True, target_rejected=True)
check("기대='403' + 출력 403 + target_rejected → hit", r1 == "hit")
check("기대한 거부는 miss 누적 안 됨(stuck 방지)", L1.get("H1").misses == 0)

L2 = ledger_with("admin login form appears")
r2 = L2.record("H1", "curl -i https://t/x", "HTTP/1.1 404 Not Found", ran=True, target_rejected=True)
check("기대 안 한 404 거부 → miss(기존 동작 보존)", r2 == "miss")

L3 = ledger_with("'Welcome admin' dashboard")
r3 = L3.record("H1", "curl https://t/", "<h1>Welcome admin</h1> dashboard", ran=True, target_rejected=False)
check("정상 신호 일치 → hit(회귀 가드)", r3 == "hit")

L4 = ledger_with("returns 403 Forbidden")
r4 = L4.record("H1", "curl https://t/admin", "", ran=True, target_rejected=True)
check("빈 출력 → miss(판단불가 아님)", r4 == "miss")

L5 = ledger_with("")   # 기대 신호 없음(추출 불가) → 판단 보류
r5 = L5.record("H1", "curl https://t/", "totally unrelated bytes xyz", ran=True, target_rejected=False)
check("신호어 없음 + 거부 아님 → neutral(판단 보류)", r5 == "neutral")


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
