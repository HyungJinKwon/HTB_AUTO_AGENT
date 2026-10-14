# 실행: htb-agent 디렉토리에서  python3 tests/test_foothold_prelisten.py
#
# 적대적 검토 교정 회귀 테스트:
#  #1 (MED) revshell 채널 모듈 — PoC(리버스셸 트리거) 발사 '전에' 리스너 선기동(listener-first).
#           과거엔 트리거가 _exploit_run_stage 에서 먼저 터지고 리스너는 _acquire_session 에서야
#           떠, 콜백이 이미 닫힌 포트로 가 유실됐다. 선기동→콜백 보관→_acquire_session 소비를 고정.
#  #3 (LOW) rce_url 이 캡처됐으면 web_product 가 비어도 웹 RCE 분기로 진입(수동 --poc 웹셸 드롭).
# 실 소켓 없이 catcher/세션을 주입해 생성 전용 로직만 검증(네트워크 없음).
import re
import sys

sys.path.insert(0, "src")
from htb_agent.exploit_modules import ExploitModule  # noqa: E402
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


def make_orc(**kw):
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    opts = {"exploit_exec": True, "auto_poc": True, "catch_revshell": True}
    opts.update(kw)   # 호출측 kw 가 기본값을 덮어쓴다
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")),
                       KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                       is_tool_available=lambda b: True, quiet=True, **opts)
    orc.world = WorldModel(target=T)   # web_product 비어있음
    orc._revshell_prefire_delay = 0    # 테스트: bind 여유 생략
    return orc


def report_with_revshell():
    rep = OrchestrationReport(target=T)
    rep.revshell_lhost = "10.10.14.9"
    rep.revshell_lport = 4444
    return rep


def session_with(transport_reply):
    """콜백받은 '진짜' ReverseShellSession 흉내 — 가짜 transport(프레이밍/마커 실경로)."""
    def transport(framed: str) -> str:
        m = re.search(r"(__HTBDONE_[0-9a-f]+_)", framed)
        marker = m.group(1) if m else "__HTBDONE_x_"
        return transport_reply + "\n" + marker + "0\n"
    s = ReverseShellSession("10.10.14.9", 4444)
    s.attach(transport)
    return s


print("=== #1 revshell 채널 모듈 → PoC 발사 전 리스너 선기동 + 콜백 보관 ===")
orc = make_orc()
orc._active_exploit_module = ExploitModule(cve="CVE-2099-0001", product="acme",
                                           channel="revshell")
orc.poc_commands = ["echo trigger-fired"]
order = []
fired = {"poc": False}
# FakeRunner 를 통해 PoC 가 '언제' 실행됐는지 기록(선기동이 그보다 먼저여야 한다).
orc.runner = FakeRunner(lambda c: order.append("poc") or RunOutput(c, "ok"))
good = session_with("uid=0(root) gid=0(root)")
def _catch(lhost, lport, timeout=None):
    order.append("listen")   # 리스너 기동 시점 기록
    return good
orc._revshell_catcher = _catch
rep = report_with_revshell()
orc._exploit_run_stage(rep, None)
check("선기동 콜백 세션을 _prelistened_revshell 로 보관",
      getattr(orc, "_prelistened_revshell", None) is good)
check("리스너가 PoC 트리거 '전에' 기동(listener-first)",
      "listen" in order and "poc" in order and order.index("listen") < order.index("poc"))

print("\n=== #1 _acquire_session 이 선기동 세션을 성립검증 후 소비 ===")
s = orc._acquire_session(rep, None)
check("성립검증 통과 → 선기동 세션 반환", s is good and s.alive)
check("1회 소비 후 _prelistened_revshell 비움", getattr(orc, "_prelistened_revshell", None) is None)
check("반환 세션으로 명령 실행 가능", "uid=0(root)" in s.run("id"))

print("\n=== #1 선기동 세션이 헛발판이면 폐기 → 일반 분기로 ===")
orc2 = make_orc()
orc2._active_exploit_module = ExploitModule(cve="CVE-2099-0002", product="acme",
                                            channel="revshell")
orc2.poc_commands = ["echo x"]
dead = session_with("<html>login</html>")
orc2._revshell_catcher = lambda lhost, lport, timeout=None: dead
rep2 = report_with_revshell()
orc2._exploit_run_stage(rep2, None)
# 소비 측 성립검증에서 헛발판 → None + close, 그 뒤 _acquire_reverse_shell 재시도(콜백 없음=None)
orc2._revshell_catcher = lambda lhost, lport, timeout=None: None  # 폴백 리스너는 콜백 없음
s2 = orc2._acquire_session(rep2, None)
check("헛발판 선기동 세션 → 폐기(None)", s2 is None)
check("헛발판 세션 close 됨", not dead.alive)

print("\n=== #1 웹 채널 모듈(channel=web)엔 선기동 없음(회귀 방지) ===")
orc3 = make_orc()
orc3._active_exploit_module = ExploitModule(cve="CVE-2099-0003", product="acme", channel="web")
orc3.poc_commands = ["echo x"]
def _boom(*a, **k):
    raise AssertionError("web 채널 모듈엔 선기동 catcher 가 호출되면 안 됨")
orc3._revshell_catcher = _boom
orc3._exploit_run_stage(report_with_revshell(), None)   # catcher 미호출이어야 통과
check("web 채널 → 선기동 세션 없음", getattr(orc3, "_prelistened_revshell", None) is None)

print("\n=== #1 catch_revshell OFF → 선기동 없음 ===")
orc4 = make_orc(catch_revshell=False)
orc4._active_exploit_module = ExploitModule(cve="CVE-2099-0004", product="acme",
                                            channel="revshell")
orc4.poc_commands = ["echo x"]
orc4._revshell_catcher = _boom
orc4._exploit_run_stage(report_with_revshell(), None)
check("catch_revshell=False → 선기동 catcher 미호출", getattr(orc4, "_prelistened_revshell", None) is None)

print("\n=== #3 rce_url 캡처 시 web_product 없어도 웹 RCE 분기 진입 ===")
orc5 = make_orc()
orc5.world.web_product = ""        # 핑거프린트 미식별
orc5.rce_url = "https://t/shell.php"
web_called = {"n": 0}
good5 = session_with("uid=33(www-data)")
def _fake_web(report, lls, vpc):
    web_called["n"] += 1
    return good5
orc5._acquire_web_rce = _fake_web
s5 = orc5._acquire_session(report_with_revshell(), None)
check("rce_url 있으면 web_product 비어도 웹 분기 진입", web_called["n"] == 1 and s5 is good5)

print("\n=== #3 web_product·rce_url 모두 없으면 웹 분기 생략(기존 동작) ===")
orc6 = make_orc()
orc6.world.web_product = ""
# rce_url 미설정
orc6._acquire_web_rce = lambda *a, **k: (_ for _ in ()).throw(AssertionError("웹 분기 호출 금지"))
orc6._revshell_catcher = lambda lhost, lport, timeout=None: None   # 리버스셸 분기로 → 콜백없음
s6 = orc6._acquire_session(report_with_revshell(), None)
check("web_product·rce_url 모두 없음 → 웹 분기 생략(리버스셸 폴백)", s6 is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
