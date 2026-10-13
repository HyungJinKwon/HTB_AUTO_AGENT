# 실행: htb-agent 디렉토리에서  python3 tests/test_flag_read.py
#
# E단계 — 플래그 읽기를 ShellSession 으로(채널 무관). 가짜 세션으로 글루·분류를 검증(생성 전용).
import sys
sys.path.insert(0, "src")
from htb_agent.flag_read import flag_read_commands, read_flags   # noqa: E402
from htb_agent.shell_session import ShellSession                 # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

U = "a" * 32   # user flag (32-hex)
R = "b" * 32   # root flag


class FakeSession(ShellSession):
    """테스트용 가짜 발판 — cmd 에 맞춰 정해진 출력을 돌려준다(실제 실행 없음)."""
    def __init__(self, table, alive=True):
        self._table = table
        self._alive = alive
        self.calls = []
    @property
    def alive(self):
        return self._alive
    def run(self, cmd):
        self.calls.append(cmd)
        for key, val in self._table.items():
            if key in cmd:
                return val
        return ""


print("=== flag_read_commands ===")
check("boot2root → user+root 읽기 명령", any("user.txt" in c for c in flag_read_commands())
      and any("root.txt" in c for c in flag_read_commands()))
check("single → flag 읽기", any("flag" in c for c in flag_read_commands("single")))
check("boot2root → 바운디드 find 폴백 포함(비표준 위치 커버)",
      any("find" in c and "user.txt" in c for c in flag_read_commands())
      and any("find" in c and "root.txt" in c for c in flag_read_commands()))
check("single → 바운디드 find 폴백 포함", any("find" in c for c in flag_read_commands("single")))
check("폴백은 깊이 제한(maxdepth) — 전체 스캔 아님",
      all("-maxdepth" in c for c in flag_read_commands() if c.strip().startswith("find")))

print("\n=== read_flags (채널 무관) ===")
# user.txt·root.txt 를 가진 발판(리버스셸이든 웹RCE든 인터페이스만 보면 동일)
sess = FakeSession({"user.txt": U, "root.txt": R})
res = read_flags(sess)
check("user 플래그 수집", res.get("user") == U)
check("root 플래그 수집", res.get("root") == R)

# user 만 읽히는 발판(권한 부족으로 root.txt 못 읽음)
only_user = FakeSession({"user.txt": U, "root.txt": ""})
ru = read_flags(only_user)
check("user 만 수집(root 없음)", ru.get("user") == U and "root" not in ru)

# 죽은/없는 세션 → 빈 결과(섣부른 실행 없음)
check("alive=False → 빈 결과·실행 안 함", read_flags(FakeSession({}, alive=False)) == {})
dead = FakeSession({}, alive=False)
read_flags(dead)
check("죽은 세션은 run 호출 안 함", dead.calls == [])
check("None 세션 안전", read_flags(None) == {})

# 둘 다 모이면 조기 종료(불필요한 run 억제)
both = FakeSession({"~/user.txt": U, "/root/root.txt": R})
read_flags(both)
check("user+root 확보 후 조기 종료(일부 명령만 실행)",
      len(both.calls) < len(flag_read_commands()))

# run 예외는 흡수하고 계속
class Flaky(FakeSession):
    def run(self, cmd):
        self.calls.append(cmd)
        if "~/user.txt" in cmd:
            raise RuntimeError("broken pipe")
        if "/home/*/user.txt" in cmd:
            return U
        return ""
fl = Flaky({})
rf = read_flags(fl)
check("run 예외 흡수 후 다음 명령으로", rf.get("user") == U)

# single 모드
sg = FakeSession({"flag.txt": "FLAG{abc}"})
check("single 모드 flag 수집", read_flags(sg, flag_kind="single").get("flag") == "FLAG{abc}")

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
import htb_agent.flag_read as fr  # noqa: E402
for mod in ("subprocess", "socket", "os", "requests", "paramiko"):
    check(f"실행/네트워크 모듈 미임포트: {mod!r}", not hasattr(fr, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
