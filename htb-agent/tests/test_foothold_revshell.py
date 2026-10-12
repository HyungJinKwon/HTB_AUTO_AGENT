# 실행: htb-agent 디렉토리에서  python3 tests/test_foothold_revshell.py
#
# 역쉘 수신 발판 배선(_acquire_reverse_shell) — 실 소켓 없이 catcher 를 주입해 검증한다.
# 실제 소켓 accept/recv 는 shell_transport.catch_reverse_shell(RCE 실행 표면). 여기선 그 자리에
# 가짜 catcher 를 주입하고, 반환 세션은 '진짜' ReverseShellSession + 가짜 transport 로 프레이밍/
# 성립검증까지 실제 경로를 태운다(생성 전용 로직만, 네트워크 없음).
import re
import socket
import sys

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.shell_session import ReverseShellSession  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.1.5"


def make_orc(catch_revshell=True):
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")),
                       KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                       is_tool_available=lambda b: True, quiet=True,
                       auto_poc=True, catch_revshell=catch_revshell)
    orc.world = WorldModel(target=T)   # web_product 비어있음 → 웹 RCE 분기 건너뜀
    return orc


def report_with_revshell():
    rep = OrchestrationReport(target=T)
    rep.revshell_lhost = "10.10.14.9"
    rep.revshell_lport = 4444
    return rep


def session_with(transport_reply):
    """콜백을 받은 '진짜' ReverseShellSession 을 흉내 — 가짜 transport 주입(프레이밍/마커 실경로)."""
    def transport(framed: str) -> str:
        m = re.search(r"(__HTBDONE_[0-9a-f]+_)", framed)
        marker = m.group(1) if m else "__HTBDONE_x_"
        return transport_reply + "\n" + marker + "0\n"   # 본문 + 완료마커 + rc0
    s = ReverseShellSession("10.10.14.9", 4444)
    s.attach(transport)
    return s


print("=== catch_revshell OFF → 소켓/ catcher 미접촉(기본 흐름 비차단) ===")
orc = make_orc(catch_revshell=False)
def _boom(*a, **k):
    raise AssertionError("catcher 가 호출되면 안 됨")
orc._revshell_catcher = _boom
check("catch_revshell=False → None(생략)", orc._acquire_session(report_with_revshell(), None) is None)

print("\n=== ON + revshell 컨텍스트 없음 → None + 안내 ===")
orc2 = make_orc()
orc2._revshell_catcher = _boom
rep_no = OrchestrationReport(target=T)   # revshell_lhost/lport 미설정
check("revshell 미준비 → None", orc2._acquire_session(rep_no, None) is None)
check("안내 수동제안 남김", any("리버스셸 수신 비활성" in s for s in rep_no.manual_suggestions))

print("\n=== ON + 콜백 세션이 성립검증 통과 → 세션 반환 ===")
orc3 = make_orc()
good = session_with("uid=0(root) gid=0(root)")
orc3._revshell_catcher = lambda lhost, lport: good
rep3 = report_with_revshell()
s3 = orc3._acquire_session(rep3, None)
check("성립 검증 통과 → 세션 반환", s3 is good and s3.alive)
check("반환 세션으로 명령 실행 가능", "uid=0(root)" in s3.run("id"))

print("\n=== ON + 헛발판(웹페이지 응답) → None + 세션 폐기 ===")
orc4 = make_orc()
dead = session_with("<html><body>login</body></html>")
orc4._revshell_catcher = lambda lhost, lport: dead
s4 = orc4._acquire_session(report_with_revshell(), None)
check("헛발판 → None", s4 is None)
check("헛발판 세션은 close 됨", not dead.alive)

print("\n=== ON + 콜백 없음(accept 타임아웃=OSError) → None(크래시 아님) ===")
orc5 = make_orc()
def _timeout(lhost, lport):
    raise socket.timeout("no callback")
orc5._revshell_catcher = _timeout
check("타임아웃 → None(안전 degrade)", orc5._acquire_session(report_with_revshell(), None) is None)

print("\n=== 웹 RCE 분기 우선 — web_product 있으면 그쪽 먼저(역쉘 catcher 미호출) ===")
orc6 = make_orc()
orc6.world.web_product = "FreePBX"
orc6.rce_url = "https://t/x"
# 웹 RCE http_fn 을 성립검증 통과하도록 주입 대신, catcher 가 호출되지 않음을 확인하기 위해
# web_http_fn 을 가로채는 대신 여기서는 '웹 분기가 먼저 시도된다'만 검증(catcher boom).
orc6._revshell_catcher = _boom
# 웹 분기는 requests 미설치면 None 반환 후 역쉘로 넘어가며 catcher(_boom) 호출 → AssertionError.
# requests 설치/미설치 무관하게, web_product 가 있을 때 '웹 분기를 먼저' 태운다는 사실만 본다.
# (requests 미설치 환경에선 역쉘로 폴백되므로 이 케이스는 웹 분기 성공 여부에 의존하지 않도록 생략)
try:
    import requests  # noqa: F401
    _has_requests = True
except ImportError:
    _has_requests = False
if _has_requests:
    # requests 있으면 web_http_fn 이 실제 네트워크를 타려 하므로, 대신 catcher 미호출만 보장하려
    # _acquire_web_rce 를 성공 세션으로 모킹한다.
    orc6._acquire_web_rce = lambda *a, **k: good
    check("web_product 있으면 웹 세션 우선 반환(역쉘 catcher 미호출)",
          orc6._acquire_session(report_with_revshell(), None) is good)
else:
    check("requests 미설치 — 웹 우선 케이스 스킵(환경)", True)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
