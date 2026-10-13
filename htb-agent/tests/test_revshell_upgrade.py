# 실행: htb-agent 디렉토리에서  python3 tests/test_revshell_upgrade.py
#
# 웹 RCE → 리버스셸 업그레이드(Commit 4, nc 4444 자동화): 리스너를 백그라운드로 띄우고 웹셸로
# 리버스셸 트리거를 쏜 뒤 콜백을 수신해 더 안정적인 셸로 승격한다. 실제 소켓 없음 — catcher 와
# 웹 fire 를 주입해 배선(발사 wrap·성립검증·웹세션 처리·재진입 가드)만 검증한다.
import re
import sys
import threading

sys.path.insert(0, "src")
from htb_agent import revshell                           # noqa: E402
from htb_agent.knowledge import KnowledgeBase            # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard             # noqa: E402
from htb_agent.session_verify import looks_like_shell, verify_probe_command  # noqa: E402
from htb_agent.shell_session import ReverseShellSession  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.245.100"
LHOST, LPORT = "10.10.14.9", 4444


def session_with(reply):
    """가짜 transport 를 주입한 '진짜' ReverseShellSession(프레이밍/마커 실경로)."""
    def transport(framed):
        m = re.search(r"(__HTBDONE_[0-9a-f]+_)", framed)
        marker = m.group(1) if m else "__HTBDONE_x_"
        return reply + "\n" + marker + "0\n"
    s = ReverseShellSession(LHOST, LPORT)
    s.attach(transport)
    return s


class FakeWeb:
    def __init__(self):
        self.fired = []
        self.closed = False
        self.evt = threading.Event()

    def fire(self, cmd):
        self.fired.append(cmd)
        self.evt.set()
        return ""

    def close(self):
        self.closed = True

    @property
    def alive(self):
        return not self.closed


def make_orc():
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")), KnowledgeBase.load(),
                       auto_approve_in_scope, is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True, catch_revshell=True)
    orc.world = WorldModel(target=T)
    orc._revshell_prefire_delay = 0      # 테스트는 bind 대기 생략
    orc._revshell_join_timeout = 5
    return orc


def fresh_report():
    rep = OrchestrationReport(target=T)
    rep.revshell_lhost = LHOST
    rep.revshell_lport = LPORT
    rep.revshells = revshell.generate(LHOST, LPORT)
    return rep


print("=== 성공: 콜백 수신·성립검증 통과 → 리버스셸로 승격, 웹 세션 close ===")
orc = make_orc()
good = session_with("uid=0(root) gid=0(root)")
orc._revshell_catcher = lambda lhost, lport: good
rep = fresh_report()
fw = FakeWeb()
res = orc._maybe_upgrade_revshell(rep, fw, looks_like_shell, verify_probe_command)
check("리버스셸 세션 반환", res is good and res.alive)
check("웹 세션 close 됨(리버스셸 우선)", fw.closed)
fw.evt.wait(2)
check("웹셸로 트리거 발사(백그라운드 wrap + /dev/tcp 콜백)",
      any("setsid" in c and f"/dev/tcp/{LHOST}/{LPORT}" in c for c in fw.fired))
check("업그레이드 성립 수동제안 남김",
      any("리버스셸 업그레이드 성립" in s for s in rep.manual_suggestions))

print("\n=== 재진입 가드: 2번째 호출은 None(한 세션 1회) ===")
fw2 = FakeWeb()
res2 = orc._maybe_upgrade_revshell(fresh_report(), fw2, looks_like_shell, verify_probe_command)
check("2번째 시도는 None", res2 is None)
check("2번째는 발사 안 함", not fw2.fired)

print("\n=== catch_revshell OFF → 시도 안 함(웹 세션 유지) ===")
orcoff = make_orc()
orcoff.catch_revshell = False
orcoff._revshell_catcher = lambda l, p: good
fwoff = FakeWeb()
check("OFF → None", orcoff._maybe_upgrade_revshell(fresh_report(), fwoff,
      looks_like_shell, verify_probe_command) is None)
check("OFF → 발사 없음", not fwoff.fired)
check("OFF → 웹 세션 유지(close 안 함)", not fwoff.closed)

print("\n=== revshell 미준비(lhost 없음) → None ===")
orcnp = make_orc()
orcnp._revshell_catcher = lambda l, p: good
repnp = OrchestrationReport(target=T)   # revshell_lhost 미설정
check("미준비 → None",
      orcnp._maybe_upgrade_revshell(repnp, FakeWeb(), looks_like_shell, verify_probe_command) is None)

print("\n=== 헛발판(웹 로그인 페이지 콜백) → None, 웹 세션 유지, 헛세션 close ===")
orcbad = make_orc()
dead = session_with("<html><body>login</body></html>")
orcbad._revshell_catcher = lambda l, p: dead
fwbad = FakeWeb()
resbad = orcbad._maybe_upgrade_revshell(fresh_report(), fwbad, looks_like_shell, verify_probe_command)
check("헛발판 → None", resbad is None)
check("헛발판 → 웹 세션 유지(close 안 함)", not fwbad.closed)
check("헛발판 리버스셸 세션은 close", not dead.alive)

print("\n=== 콜백 없음(catcher None 반환) → None(크래시 아님) ===")
orcnone = make_orc()
orcnone._revshell_catcher = lambda l, p: None
check("콜백 없음 → None",
      orcnone._maybe_upgrade_revshell(fresh_report(), FakeWeb(),
                                      looks_like_shell, verify_probe_command) is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
