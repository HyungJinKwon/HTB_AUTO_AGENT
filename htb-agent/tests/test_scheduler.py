# 실행: htb-agent 디렉토리에서  python3 tests/test_scheduler.py
#
# S3 — 의존 선언형 스테이지 스케줄러: 순서·재실행(dirty)·고정점·종료·중단을 고정한다.
import sys
sys.path.insert(0, "src")
from htb_agent.scheduler import Stage, StageScheduler   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 선언 순서대로 실행(생산자→소비자) ===")
order = []
w = {"prod": "", "ver": ""}
sched = StageScheduler([
    Stage("fp",   run=lambda: (order.append("fp"), w.__setitem__("prod", "freepbx")),
          ready=lambda: not w["prod"], key=lambda: (w["prod"],)),
    Stage("probe", run=lambda: (order.append("probe"), w.__setitem__("ver", "16.0")),
          ready=lambda: bool(w["prod"]) and not w["ver"], key=lambda: (w["prod"],)),
    Stage("lookup", run=lambda: order.append("lookup"),
          ready=lambda: bool(w["prod"]), key=lambda: (w["prod"],)),
])
fired = sched.run_to_fixpoint()
check("fp 가 소비자보다 먼저", order and order[0] == "fp")
check("생산 후 소비자 활성 — 한 run_to_fixpoint 에서 체인 완주", order == ["fp", "probe", "lookup"])
check("실행 수 = 3", fired == 3)

print("\n=== 입력 불변이면 재실행 안 함(멱등) ===")
fired2 = sched.run_to_fixpoint()
check("재호출 시 0건(모든 key 불변)", fired2 == 0)

print("\n=== 입력(key)이 바뀌면 그 스테이지만 재실행(dirty) ===")
order.clear()
w["prod"] = "wordpress"      # 제품 변경 → fp 는 ready=False(이미 prod 있음), probe/lookup 은 key 변화
# fp: ready=not prod=False → 안 돎. probe: ready=prod and not ver → ver 비움
w["ver"] = ""
fired3 = sched.run_to_fixpoint()
check("key 바뀐 probe·lookup 재실행", set(order) == {"probe", "lookup"})
check("fp 는 ready=False 라 미실행", "fp" not in order)

print("\n=== should_stop: 즉시 중단 ===")
order.clear()
w2 = {"prod": "", "ver": ""}
calls = {"n": 0}
def _stop():
    calls["n"] += 1
    return True   # 항상 중단
s2 = StageScheduler([
    Stage("a", run=lambda: order.append("a"), ready=lambda: True, key=lambda: (1,)),
])
fired4 = s2.run_to_fixpoint(_stop)
check("should_stop True → 아무것도 실행 안 함", fired4 == 0 and order == [])

print("\n=== max_passes 안전 상한: 항상 dirty 여도 유한 종료 ===")
# key 가 매 호출 달라지는 병리적 스테이지 → 패스마다 1회, max_passes 로 bound.
tick = {"n": 0}
s3 = StageScheduler([
    Stage("ever", run=lambda: tick.__setitem__("n", tick["n"] + 1),
          ready=lambda: True, key=lambda: (tick["n"],)),  # 실행할 때마다 key 증가
], max_passes=4)
fired5 = s3.run_to_fixpoint()
check("병리적 dirty 도 max_passes 로 유한", fired5 == 4)

print("\n=== ready=False 스테이지는 전제 충족 전까지 대기 ===")
gate = {"open": False}
hit = []
s4 = StageScheduler([
    Stage("gated", run=lambda: hit.append(1),
          ready=lambda: gate["open"], key=lambda: (gate["open"],)),
])
check("닫힘 상태에선 미실행", s4.run_to_fixpoint() == 0 and hit == [])
gate["open"] = True
check("열리면 1회 실행", s4.run_to_fixpoint() == 1 and hit == [1])

print("\n=== reset: 실행 이력 초기화 ===")
s4.reset()
check("reset 후 같은 입력도 다시 실행 대상", s4.run_to_fixpoint() == 1 and hit == [1, 1])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
