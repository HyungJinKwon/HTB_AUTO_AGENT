# 실행: htb-agent 디렉토리에서  python3 tests/test_phase_prune.py
#
# [T2-a] 전제 가설 기각 시 하류 가설 보류(dep prune) + [T2-d] 궤적 드리프트 supervisor advisory.
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import recommend  # noqa: E402
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


print("=== [T2-a] dep_blocked: 전제 기각 시 하류 보류 ===")
led = HypothesisLedger(items=[H("H1", status="rejected"), H("H2", depends_on=["H1"])])
check("전제 H1 기각 → H2 dep_blocked", led.dep_blocked(led.get("H2")) is True)
check("focus() 가 H2 를 건너뜀(쫓을 것 없음)", led.focus() is None)

led2 = HypothesisLedger(items=[H("H1", status="pending"), H("H2", depends_on=["H1"])])
check("전제 H1 살아있으면 H2 보류 아님", led2.dep_blocked(led2.get("H2")) is False)
check("focus() 는 H1(우선순위·ID)", led2.focus().id == "H1")

print("\n=== self-dep·미존재 전제는 무시 ===")
check("자기참조 무시", HypothesisLedger(items=[H("H1", depends_on=["H1"], status="rejected")])
      .dep_blocked(H("H1", depends_on=["H1"], status="rejected")) is False)
check("미존재 전제 무시",
      HypothesisLedger(items=[H("H2", depends_on=["H9"])]).dep_blocked(H("H2", depends_on=["H9"]))
      is False)

print("\n=== apply_update / from_dict depends_on 보존 ===")
led3 = HypothesisLedger()
led3.apply_update({"hypotheses": [
    {"id": "H1", "text": "t"},
    {"id": "H2", "text": "u", "depends_on": ["H1"]}]})
check("apply_update 가 depends_on 반영", led3.get("H2").depends_on == ["H1"])
rt = HypothesisLedger.from_dict(led3.to_dict())
check("to_dict/from_dict 왕복 보존", rt.get("H2").depends_on == ["H1"])

print("\n=== [T2-d] 궤적 드리프트 supervisor advisory ===")
def report(plan):
    return SimpleNamespace(blockers=[], enum_findings=[], llm_findings=[],
                           phase_status={}, manual_suggestions=[], plan=plan)

# 막힌 가설 2개 + 열린(쫓을) 가설 없음 → 드리프트 권고
drift = HypothesisLedger(items=[H("H1", status="testing", misses=5),
                                H("H2", status="testing", misses=5)])
recs = recommend.propose(report(drift))
titles = [r.title for r in recs.items]
check("막힌 가설 2+·열린 가설 0 → 드리프트 권고", any("드리프트" in t for t in titles))
check("권고 출처 supervisor", any(r.source == "supervisor" for r in recs.items))

# 열린(신선한) 가설이 있으면 드리프트 아님
ok = HypothesisLedger(items=[H("H1", status="testing", misses=5), H("H2", status="pending")])
check("쫓을 신선한 가설 있으면 드리프트 없음",
      not any("드리프트" in r.title for r in recommend.propose(report(ok)).items))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
