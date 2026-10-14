# 실행: htb-agent 디렉토리에서  python3 tests/test_e2e_real_foothold.py
#
# ★ 가짜(fake) 주입이 아닌 '진짜' end-to-end 검증 — 단위 테스트가 놓친 실 경로를 잡는다.
# 배경: urllib3/requests 미설치로 웹 RCE 발판이 조용히 degrade 돼 실제 머신에서 user 플래그를
#   못 찾았다(단위 테스트는 http_fn 을 가짜로 주입해 이 경로를 한 번도 실행 안 함).
# 이 테스트는 실 HTTP 웹셸을 loopback 에 띄우고, 실제 requests(web_http_fn) → WebRceSession →
#   발판 성립 검증 → flag_read.read_flags 로 user 플래그까지 '진짜로' 읽어 그 재발을 막는다.
# requests 미설치 환경(코어 전용 CI)에서는 skip — 전용 CI 잡(foothold-e2e)이 requests 를 깔고 돌린다.
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse

sys.path.insert(0, "src")

passed = failed = skipped = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")
def skip(name, why):
    global skipped
    skipped += 1; print(f"  ⏭  {name} — 건너뜀({why})")


try:
    import requests  # noqa: F401
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from htb_agent import flag_read, poc_fetch                              # noqa: E402
from htb_agent.session_verify import looks_like_shell, verify_probe_command  # noqa: E402
from htb_agent.shell_session import WebRceSession                       # noqa: E402

FLAG = "a1b2c3d4e5f60718293a4b5c6d7e8f90"   # HTB user.txt 형식(32-hex)


class _Shell(http.server.BaseHTTPRequestHandler):
    """진짜 '?cmd=' 웹셸: 받은 cmd 를 sh -c 로 실제 실행해 stdout 반환(post-exploit RCE 흉내)."""
    home = ""

    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        cmd = (urllib.parse.parse_qs(q.query).get("cmd") or [""])[0]
        if q.path != "/shell.php" or not cmd:
            self.send_response(404); self.end_headers(); self.wfile.write(b"nf"); return
        try:
            r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True,
                               timeout=10, env=dict(os.environ, HOME=self.home))
            body = (r.stdout + r.stderr).encode()
        except Exception as e:   # noqa: BLE001
            body = str(e).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


print("=== 실 pip 경로(주입 아님) — ensure_module / _pip_install ===")
# 이미 설치된 'pip' 로 실 subprocess+pip 호출(네트워크/변경 없음, 'already satisfied' → True).
check("_pip_install('pip') 실 subprocess rc0", poc_fetch._pip_install("pip") is True)
check("ensure_module('os') 실 find_spec → True(설치 미호출)", poc_fetch.ensure_module("os") is True)
check("missing_module 실 파싱",
      poc_fetch.missing_module("ModuleNotFoundError: No module named 'urllib3'") == "urllib3")

print("\n=== 실 HTTP 웹셸 발판 체인 (가짜 없음: requests → WebRceSession → read_flags) ===")
if not _HAS_REQUESTS:
    skip("실 웹 RCE 발판 e2e", "requests 미설치(코어 전용) — 전용 CI 잡 foothold-e2e 가 커버")
else:
    from htb_agent.shell_transport import web_http_fn
    home = tempfile.mkdtemp()
    with open(os.path.join(home, "user.txt"), "w") as f:
        f.write(FLAG + "\n")
    _Shell.home = home
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Shell)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        url = f"http://127.0.0.1:{port}/shell.php"
        ws = WebRceSession(url, "cmd", method="GET", inject="query")
        ws.attach(web_http_fn)        # ← 진짜 requests HTTP (degrade 사고 지점)
        probe = ws.run(verify_probe_command())
        check("웹셸 실 HTTP 왕복 성공(빈 출력 아님)", bool(probe.strip()))
        check("발판 성립 검증 looks_like_shell=True(실 id/uname)", looks_like_shell(probe))
        check("echo 왕복 정확(프레이밍/마커 실경로)", ws.run("echo __PONG__").strip().endswith("__PONG__"))
        flags = flag_read.read_flags(ws, flag_kind="boot2root")
        check("read_flags 가 user 플래그 실 읽기(cat ~/user.txt)", flags.get("user") == FLAG)
    finally:
        srv.shutdown(); th.join(timeout=5)

print(f"\n결과: {passed} passed, {failed} failed, {skipped} skipped")
sys.exit(1 if failed else 0)
