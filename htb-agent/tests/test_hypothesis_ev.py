# 실행: htb-agent 디렉토리에서  python3 tests/test_hypothesis_ev.py
#
# [T1-b] 가설 기대값(EV) 점수화 — redcat2 confidence×impact÷cost 의 결정적 이식.
# · EV = (신뢰도 priority × 영향 impact ÷ 비용 cost) × 최근결과 보정(misses 감쇠)
# · focus() 는 EV 높은 순(동률 ID). 가변 증거예산 budget() 으로 막힘 판정.
# · 전부 '중'·misses=0 이면 기존 우선순위 정렬·고정 임계와 동일(하위호환).
import sys

sys.path.insert(0, "src")
from htb_agent.hypotheses import Hypothesis, HypothesisLedger  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def H(hid, **kw):
    return Hypothesis(id=hid, text=f"가설 {hid}", **kw)


print("=== EV 기본값(전부 중) = 신뢰도 가중치 (하위호환) ===")
check("중/중/중 → ev 2.0", abs(H("H1").ev - 2.0) < 1e-9)
check("상 priority → ev 3.0", abs(H("H1", priority="상").ev - 3.0) < 1e-9)
check("하 priority → ev 1.0", abs(H("H1", priority="하").ev - 1.0) < 1e-9)

print("\n=== impact↑·cost↓ 가 EV 를 올린다 ===")
check("impact상 → 2*3/2=3.0", abs(H("H1", impact="상").ev - 3.0) < 1e-9)
check("cost하 → 2*2/1=4.0", abs(H("H1", cost="하").ev - 4.0) < 1e-9)
check("impact상·cost하 → 2*3/1=6.0", abs(H("H1", impact="상", cost="하").ev - 6.0) < 1e-9)

print("\n=== misses 감쇠(완전 막히기 전 신선한 각도 우선) ===")
check("misses=1 → 2/1.5", abs(H("H1").ev - 2/1.5 * 1) > 0 and abs(H("H1", misses=1).ev - (2/1.5)) < 1e-9)
check("misses 클수록 EV 감소", H("H1", misses=1).ev > H("H1", misses=3).ev)

print("\n=== focus(): EV 높은 순, 동률은 ID ===")
led = HypothesisLedger(items=[H("H1"), H("H2", impact="상")])  # H2 ev=3 > H1 ev=2
check("impact 높은 H2 를 먼저 쫓는다", led.focus().id == "H2")
led2 = HypothesisLedger(items=[H("H1"), H("H2")])              # 동률
check("동률이면 ID 오름차순(H1)", led2.focus().id == "H1")
# misses 가 H1 을 끌어내려 H2 로 초점 이동(둘 다 막힘 아님: 중/중 budget=2, miss=1<2)
led3 = HypothesisLedger(items=[H("H1", misses=1), H("H2")])
check("H1 misses 로 EV↓ → 초점이 H2 로", led3.focus().id == "H2")

print("\n=== 하위호환: 전부 중·misses0 이면 priority 정렬과 동일 ===")
ledc = HypothesisLedger(items=[H("H2", priority="중"), H("H1", priority="상"), H("H3", priority="하")])
order = [ledc.focus().id]
check("상 우선(H1) 먼저", order == ["H1"])

print("\n=== 가변 증거예산 budget() ===")
led4 = HypothesisLedger(replan_after=2)
check("중/중 → budget 2 (기존과 동일)", led4.budget(H("Hx")) == 2)
check("impact상·cost하 → budget round(2*3/1)=6", led4.budget(H("Hx", impact="상", cost="하")) == 6)
check("impact하·cost상 → budget round(2*1/3)=1(최소 보장)", led4.budget(H("Hx", impact="하", cost="상")) == 1)

print("\n=== stuck() 가 가설별 가변 예산을 쓴다 ===")
# 저가치(impact하/cost상 → budget1)는 miss 1 에 막힘, 기본(중/중 budget2)은 miss1 엔 아직 안 막힘
cheap = H("H1", impact="하", cost="상", status="testing", misses=1)
norm = H("H2", status="testing", misses=1)
led5 = HypothesisLedger(items=[cheap, norm])
stuck_ids = {h.id for h in led5.stuck()}
check("저가치 가설은 miss1 에 막힘", "H1" in stuck_ids)
check("기본 가설은 miss1 엔 아직 안 막힘", "H2" not in stuck_ids)

print("\n=== apply_update / from_dict 가 impact·cost 를 보존 ===")
led6 = HypothesisLedger()
led6.apply_update({"hypotheses": [
    {"id": "H1", "text": "t1", "priority": "상", "impact": "상", "cost": "하"}]})
h = led6.get("H1")
check("apply_update 신규가 impact·cost 반영", h.impact == "상" and h.cost == "하")
led6.apply_update({"hypotheses": [{"id": "H1", "impact": "중"}]})
check("apply_update 기존 impact 갱신", led6.get("H1").impact == "중" and led6.get("H1").cost == "하")
round_trip = HypothesisLedger.from_dict(led6.to_dict())
check("to_dict/from_dict 왕복 보존", round_trip.get("H1").cost == "하")
check("미지정 impact/cost 기본 '중'", HypothesisLedger.from_dict(
    {"items": [{"id": "H9", "text": "x"}]}).get("H9").impact == "중")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
