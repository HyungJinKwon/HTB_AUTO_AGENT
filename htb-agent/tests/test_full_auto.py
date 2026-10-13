# 실행: htb-agent 디렉토리에서  python3 tests/test_full_auto.py
#
# 최대 자동화(게이트 유지) 검토 후속:
#  (1) --full-auto 번들 전개(_expand_full_auto) — 실제 발사 옵트인은 명시 플래그로만.
#  (2) --autonomous 는 그 자체로 익스 발사를 암시하지 않음(인지된 옵트인 보존).
#  (3) sandbox.image_available — docker 이미지가 '이미 빌드됨'일 때만 자동선택 근거.
import sys
sys.path.insert(0, "src")
from htb_agent.main import _expand_full_auto, build_parser  # noqa: E402
from htb_agent.tools import sandbox  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

P = build_parser()

print("=== --full-auto 번들 전개 ===")
a = P.parse_args(["10.129.1.5", "--full-auto"])
_expand_full_auto(a)
check("autonomous 켜짐", a.autonomous)
check("exploit_exec 켜짐", a.exploit_exec)
check("auto_poc 켜짐", a.auto_poc)
check("catch_revshell 켜짐", a.catch_revshell)

print("\n=== --autonomous 는 익스 발사를 암시하지 않음(경계 보존) ===")
b = P.parse_args(["10.129.1.5", "--autonomous"])
_expand_full_auto(b)   # full_auto 아님 → 전개 no-op
check("autonomous 단독: exploit_exec OFF", not b.exploit_exec)
check("autonomous 단독: auto_poc OFF", not b.auto_poc)
check("autonomous 단독: catch_revshell OFF", not b.catch_revshell)

print("\n=== 기본(플래그 없음): 전부 OFF ===")
c = P.parse_args(["10.129.1.5"])
_expand_full_auto(c)
check("기본: autonomous OFF", not c.autonomous)
check("기본: exploit_exec OFF", not c.exploit_exec)

print("\n=== sandbox.image_available: 빌드돼 있을 때만 True ===")
def fake_exec(rc):
    class P2:
        returncode = rc
    return lambda *a, **k: P2()
check("이미지 존재(rc0) → True", sandbox.image_available("x:latest", exec_fn=fake_exec(0)) is True)
check("이미지 없음(rc1) → False", sandbox.image_available("x:latest", exec_fn=fake_exec(1)) is False)
def boom(*a, **k):
    raise OSError("docker not found")
check("docker 오류 → False(안전)", sandbox.image_available("x:latest", exec_fn=boom) is False)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
