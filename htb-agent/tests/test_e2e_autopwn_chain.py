# 실행: htb-agent 디렉토리에서  python3 tests/test_e2e_autopwn_chain.py
#
# E2E 통합: 내장 익스 모듈 체인을 '전체 Orchestrator.run()' 으로 구동한다(connected.htb/FreePBX).
#   vhost 핑거프린트(freepbx 16.0.40.7) → 내장 모듈 매칭(CVE-2025-57819) → 로컬 PoC 조달·실행
#   → PoC 출력에서 웹셸 URL 캡처 → 웹 RCE 발판 세션 → user.txt 자동 읽기
# 실제 네트워크 없음: FakeRunner(명령) + shell_transport.web_http_fn 주입(웹셸 HTTP). 리버스셸
# 수신(소켓)은 끄고(web-only) 결정적으로 검증한다.
import os
import re
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent import shell_transport                    # noqa: E402
from htb_agent.knowledge import KnowledgeBase            # noqa: E402
from htb_agent.orchestrator import Orchestrator          # noqa: E402
from htb_agent.scope_guard import ScopeGuard             # noqa: E402
from htb_agent.tools.recon import auto_approve_contained  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


TARGET = "10.129.245.100"
VHOST = "connected.htb"
WEBSHELL = f"http://{VHOST}/this-is-an-ioc-not-actually-watchTowr-56lzpxf2lg.php"
USERFLAG = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

NMAP = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}"/><ports>'
        f'<port protocol="tcp" portid="443"><state state="open"/>'
        f'<service name="https" product="Apache httpd"/></port></ports></host></nmaprun>')

FREEPBX_BODY = ("<html><head><title>FreePBX Administration</title></head>"
                "<body><div class='footer'>FreePBX 16.0.40.7</div>"
                "<!-- appver=16.0.40.7 --></body></html>")

POC_OUT = (f"[*] Target: https://{VHOST}/\n[*] exploiting CVE-2025-57819...\n"
           f"[+] Webshell dropped: {WEBSHELL}\n[+] Done.\n")


def fake(cmd: str) -> RunOutput:
    c = cmd or ""
    if c.startswith("nmap"):
        return RunOutput(c, stdout=NMAP)
    if "searchsploit" in c:
        return RunOutput(c, stdout="")   # 내장 모듈 경로를 태운다(searchsploit 무관)
    if ".py" in c and ("-H" in c or "poc" in c.lower() or "CVE-2025-57819" in c):
        return RunOutput(c, stdout=POC_OUT)   # 내장 모듈 PoC 호출 → 웹셸 URL 출력
    if VHOST in c and ("curl" in c or "http" in c):
        return RunOutput(c, stdout=FREEPBX_BODY)   # 핑거프린트
    return RunOutput(c, stdout="")


def fake_web_http(spec):
    """웹셸(?cmd=) HTTP 를 흉내낸다. 프레이밍된 cmd 를 보고 응답 본문 + 완료마커를 돌려준다."""
    framed = (spec.get("params") or {}).get("cmd", "") or (spec.get("data") or {}).get("cmd", "")
    m = re.search(r"(__HTBWEB_[0-9a-f]+_)", framed)
    marker = m.group(1) if m else "__HTBWEB_x_"
    if "user.txt" in framed:
        body = USERFLAG
    elif "id" in framed or "uname" in framed or "whoami" in framed:
        body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    else:
        body = ""   # 설정/DB 자격 없음·privesc 열거 공백 → 결정적
    return f"{body}\n{marker}0\n"


print("=== 전체 run(): FreePBX 핑거프린트 → CVE-2025-57819 내장모듈 → 웹셸 캡처 → user 플래그 ===")
with tempfile.TemporaryDirectory() as d:
    pf = os.path.join(d, "watchTowr-vs-FreePBX-CVE-2025-57819.py")
    with open(pf, "w") as fh:
        fh.write("#!/usr/bin/env python3\nprint('poc')\n")

    g = ScopeGuard.from_cidr_strings()
    g.bind_target(TARGET)
    orc = Orchestrator(
        g, FakeRunner(fake), KnowledgeBase.load(), auto_approve_contained,
        hosts_map={VHOST: TARGET}, flag_kind="boot2root",
        is_tool_available=lambda b: True,
        exploit_exec=True, auto_poc=True, catch_revshell=False,   # 웹 발판만(소켓 없음)
        poc_dir=d, quiet=True,
    )

    _orig = getattr(shell_transport, "web_http_fn", None)
    shell_transport.web_http_fn = fake_web_http
    try:
        rep = orc.run()
    finally:
        if _orig is not None:
            shell_transport.web_http_fn = _orig

    w = rep.world
    check("핑거프린트: web_product=freepbx", w is not None and w.web_product == "freepbx")
    check("핑거프린트: web_version 16.x", w is not None and w.web_version.startswith("16"))
    check("내장 익스 모듈 활성화(CVE-2025-57819)",
          getattr(orc, "_active_exploit_module", None) is not None
          and orc._active_exploit_module.cve == "CVE-2025-57819")
    check("PoC 호출이 실행 큐에 들어가 실행됨",
          any(".py" in (f.command or "") and "-H" in (f.command or "")
              for f in rep.enum_findings))
    check("PoC 출력에서 웹셸 URL 캡처(rce_url)", getattr(orc, "rce_url", "") == WEBSHELL)
    check("웹셸 cmd 스펙 GET/query", getattr(orc, "rce_method", "") == "GET"
          and getattr(orc, "rce_inject", "") == "query")
    check("🏁 user 플래그 자동 획득", rep.user_flag == USERFLAG)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
