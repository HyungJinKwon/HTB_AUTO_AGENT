# 실행: htb-agent 디렉토리에서  python3 tests/test_foothold_capture.py
#
# 발판 아티팩트 캡처(Commit 2): PoC 출력에서 드롭된 웹셸 URL 을 잡아 self.rce_url + 웹 RCE
# cmd 스펙(param/method/inject)으로 세팅하고, _acquire_web_rce 가 그 스펙으로 세션을 만드는지
# 검증한다. 실제 네트워크 없음(FakeRunner + web_http_fn 주입).
import re
import sys

sys.path.insert(0, "src")
from htb_agent import exploit_modules as em              # noqa: E402
from htb_agent import shell_transport                    # noqa: E402
from htb_agent.exploit_run import harvest_foothold       # noqa: E402
from htb_agent.knowledge import KnowledgeBase            # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard             # noqa: E402
from htb_agent.session_verify import looks_like_shell, verify_probe_command  # noqa: E402
from htb_agent.tools.recon import auto_approve_contained  # noqa: E402
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
WEBSHELL = f"http://{T}/this-is-an-ioc-not-actually-watchTowr-56lzpxf2lg.php"
POC_OUT = f"[*] exploiting...\n[+] Webshell dropped: {WEBSHELL}\n[*] done\n"


print("=== harvest_foothold (순수 파싱) ===")
mod = em.match("freepbx", "16.0.40.7")
check("모듈 regex 로 웹셸 URL 캡처", harvest_foothold(POC_OUT, mod) == WEBSHELL)
check("신호 없으면 ''", harvest_foothold("nothing", mod) == "")


def make_orc():
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(_fake), KnowledgeBase.load(), auto_approve_contained,
                       is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True)
    orc.world = WorldModel(target=T)
    orc.world.web_product = "freepbx"
    orc._active_exploit_module = mod
    orc.poc_commands = [f"python3 /tmp/poc.py -H http://{T}/"]
    return orc


def _fake(cmd: str) -> RunOutput:
    if "poc.py" in (cmd or ""):
        return RunOutput(cmd, stdout=POC_OUT)
    return RunOutput(cmd, stdout="")


print("\n=== _exploit_run_stage: PoC 출력에서 rce_url + cmd 스펙 캡처 ===")
orc = make_orc()
rep = OrchestrationReport(target=T)
orc._exploit_run_stage(rep, None)
check("rce_url 가 캡처됨", getattr(orc, "rce_url", "") == WEBSHELL)
check("cmd 스펙이 모듈대로(GET/query/cmd)",
      getattr(orc, "rce_method", "") == "GET"
      and getattr(orc, "rce_inject", "") == "query"
      and getattr(orc, "rce_cmd_param", "") == "cmd")
check("발판 캡처 수동제안 남김",
      any("웹 RCE 발판 캡처" in s for s in rep.manual_suggestions))


print("\n=== _acquire_web_rce: 캡처한 스펙(GET ?cmd=)으로 세션 요청 ===")
captured = {}


def _fake_http(spec):
    captured["spec"] = spec
    # 프레이밍된 cmd 에서 마커를 뽑아 '성립 신호 + 완료마커' 응답을 만든다(실셸 흉내).
    framed = (spec.get("params") or {}).get("cmd", "")
    m = re.search(r"(__HTBWEB_[0-9a-f]+_)", framed)
    marker = m.group(1) if m else "__HTBWEB_x_"
    return f"uid=33(www-data) gid=33(www-data)\n{marker}0\n"


_orig = getattr(shell_transport, "web_http_fn", None)
shell_transport.web_http_fn = _fake_http
try:
    ws = orc._acquire_web_rce(rep, looks_like_shell, verify_probe_command)
finally:
    if _orig is not None:
        shell_transport.web_http_fn = _orig

spec = captured.get("spec", {})
check("요청 URL = 캡처한 웹셸 URL", spec.get("url") == WEBSHELL)
check("메서드 GET", spec.get("method") == "GET")
check("cmd 가 query 파라미터에 주입", "cmd" in (spec.get("params") or {}))
check("성립검증 통과 → 세션 반환", ws is not None and ws.alive)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
