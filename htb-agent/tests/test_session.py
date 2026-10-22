# 실행: htb-agent 디렉토리에서  python3 tests/test_session.py
#
# tools/session.py (해커톤 lab 에서 이식) — 지속 PTY bash 세션 러너(Runner 프로토콜 호환).
# pexpect 는 선택 의존성이라 CI(stdlib)에는 없다 → 가짜 pexpect 를 주입해 run() 로직을 검증하고,
# 미설치 degrade(SessionError) 경로와 순수 헬퍼도 확인한다.
import re
import sys

sys.path.insert(0, "src")

from htb_agent.tools import session as S                    # noqa: E402
from htb_agent.tools.runner import RunOutput                # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== 순수 헬퍼 · 클래스 속성 ===")
check("_clean: CR 정규화 + 에코 명령줄 제거",
      S._clean("echo hi\r\nhi\r\n", "echo hi") == "hi")
check("ShellSession.shell = True(파이프 가능 광고)", S.ShellSession.shell is True)
check("ShellSession.contained = False(egress 강제 아님)", S.ShellSession.contained is False)
bj = S.BgJob(name="j1", pid=123, log="/tmp/j1.log", command="nmap -p-")
check("BgJob.elapsed ≥ 0", bj.elapsed >= 0)

print("\n=== pexpect 미설치면 SessionError(degrade) ===")
_real = S.pexpect
S.pexpect = None
raised = False
try:
    S.ShellSession()
except S.SessionError:
    raised = True
check("pexpect None → SessionError", raised)
S.pexpect = _real


print("\n=== 가짜 pexpect 주입 — run() 마커 프로토콜 ===")
class FakeSpawn:
    def __init__(self, *a, **k):
        self.sent: list[str] = []
        self.before = ""
        self.match = None
        self._queue: list = []        # expect() 응답 큐: (before, rc) 또는 예외 인스턴스
    def sendline(self, s): self.sent.append(s)
    def send(self, s): self.sent.append(s)
    def expect_exact(self, s, timeout=None): return 0          # _sync 통과
    def expect(self, pat, timeout=None):
        item = self._queue.pop(0) if self._queue else ("", 0)
        if isinstance(item, BaseException):
            raise item
        before, rc = item
        self.before = before
        self.match = re.search(r"(\d+)", str(rc))
        return 0
    def sendintr(self): self.sent.append("^C")
    def close(self, force=False): pass

class FakePexpect:
    TIMEOUT = type("TIMEOUT", (Exception,), {})
    EOF = type("EOF", (Exception,), {})
    _last = None
    def spawn(self, *a, **k):
        FakePexpect._last = FakeSpawn()
        return FakePexpect._last

fp = FakePexpect()
S.pexpect = fp
try:
    sess = S.ShellSession()
    check("세션 생성(가짜 spawn) alive", sess.alive)
    check("setup 명령 전송됨(stty -echo 등)", any("stty -echo" in s for s in FakePexpect._last.sent))
    # run() happy path — expect 가 (before, rc) 를 돌려주도록 큐 적재
    FakePexpect._last._queue = [("hi", 0)]
    out = sess.run("echo hi")
    check("run stdout 수집", isinstance(out, RunOutput) and out.stdout == "hi")
    check("run returncode 회수", out.returncode == 0)
    # 비정상 종료코드
    FakePexpect._last._queue = [("nope", 2)]
    check("run 비정상 rc", sess.run("false").returncode == 2)
    # 타임아웃 → timed_out + Ctrl-C 복구(가짜라 _sync 통과 → error "")
    FakePexpect._last._queue = [fp.TIMEOUT()]
    tout = sess.run("sleep 999", timeout=1)
    check("run 타임아웃 → timed_out", tout.timed_out and tout.returncode == -1)
    check("타임아웃 시 Ctrl-C 전송", "^C" in FakePexpect._last.sent)
    # 세션 종료 후 run 은 안전 실패
    sess.close()
    check("close 후 alive False", not sess.alive)
    check("close 후 run 안전 실패", sess.run("x").returncode == -1)
finally:
    S.pexpect = _real

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
