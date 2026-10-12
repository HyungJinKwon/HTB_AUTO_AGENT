# 실행: htb-agent 디렉토리에서  python3 tests/test_relaunch.py
#
# auto-relaunch: 미처리 예외 시 저장 지점부터 최대 N회 재시작(저장 복원=resume). 사용자 중단 제외.
import sys

sys.path.insert(0, "src")
from htb_agent.relaunch import run_with_relaunch  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


class FakeOrc:
    def __init__(self, fail_times, exc=RuntimeError):
        self.fail_times = fail_times
        self.exc = exc
        self.calls = 0
        self.resume = False

    def run(self):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc(f"boom {self.calls}")
        return f"ok after {self.calls}"


nap = lambda s: None  # noqa: E731 (테스트 — 실제 대기 없음)

print("=== 2회 실패 후 성공(재시작 복구) ===")
o = FakeOrc(fail_times=2)
logs = []
r = run_with_relaunch(o, max_restarts=3, log=lambda n, c, e: logs.append(n), sleep=nap)
check("3번째 시도에서 성공 반환", r == "ok after 3")
check("총 3회 호출(1+재시작2)", o.calls == 3)
check("재시작 시 resume=True 로 전환", o.resume is True)
check("재시작 로그 2회", logs == [1, 2])

print("\n=== 상한 소진 → 마지막 예외 전파 ===")
o2 = FakeOrc(fail_times=99)
raised = False
try:
    run_with_relaunch(o2, max_restarts=2, sleep=nap)
except RuntimeError as e:
    raised = "boom 3" in str(e)
check("상한(2) 소진 후 예외 전파", raised)
check("총 3회만 시도(1+2)", o2.calls == 3)

print("\n=== max_restarts=0(기본) → 재시작 없음 ===")
o3 = FakeOrc(fail_times=1)
r3 = False
try:
    run_with_relaunch(o3, max_restarts=0, sleep=nap)
except RuntimeError:
    r3 = True
check("기본 0 이면 1회만 시도(재시작 안 함)", o3.calls == 1 and r3)
o3b = FakeOrc(fail_times=0)
check("기본 0 이어도 정상 실행은 성공", run_with_relaunch(o3b, 0, sleep=nap) == "ok after 1")

print("\n=== 사용자 중단은 재시작하지 않고 전파 ===")
class Interrupter:
    def __init__(self):
        self.calls = 0
        self.resume = False
    def run(self):
        self.calls += 1
        raise KeyboardInterrupt()
oi = Interrupter()
ki = False
try:
    run_with_relaunch(oi, max_restarts=5, sleep=nap)
except KeyboardInterrupt:
    ki = True
check("KeyboardInterrupt 즉시 전파(재시작 안 함)", ki and oi.calls == 1)

se = False
class Exiter:
    resume = False
    def run(self):
        raise SystemExit(2)
try:
    run_with_relaunch(Exiter(), max_restarts=5, sleep=nap)
except SystemExit:
    se = True
check("SystemExit 즉시 전파", se)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
