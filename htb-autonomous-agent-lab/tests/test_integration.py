# 실행: htb-agent 디렉토리에서  python3 tests/test_integration.py
# main() 을 러너 주입으로 엔드투엔드 구동 — 전체 파이프라인 통합 검증.
import sys, io, tempfile, os, json
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent.main import main
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2 Ubuntu"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
  <script id="vulners" output="CVE-2011-2523"/></port>
</ports></host></nmaprun>"""

def run_main(argv, xml=LINUX):
    r = FakeRunner(lambda c: RunOutput(c, stdout=xml) if c.startswith("nmap") else RunOutput(c, stdout="ok"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv, runner=r)
    return code, buf.getvalue(), r

print("=== 전체 파이프라인 (main, 러너 주입) ===")
with tempfile.TemporaryDirectory() as d:
    code, out, r = run_main(["10.129.1.5", "--auto", "--state-dir", d])
    check("정상 종료(exit 0)", code == 0)
    check("RECON 수행", "RECON" in out)
    check("PROFILE Linux", "linux" in out.lower())
    check("VULN CVE 탐지", "CVE-2011-2523" in out)
    check("vsftpd 취약점 매핑", "vsftpd" in out.lower())
    check("상태 저장됨", os.path.isfile(os.path.join(d, "10.129.1.5.json")))

print("\n=== 범위밖 타겟 거부 (exit 2) ===")
code, out, r = run_main(["8.8.8.8", "--auto", "--no-save"])
check("범위밖 거부", code == 2)
check("nmap 호출 안 함", not any(c.startswith("nmap") for c in r.calls))

print("\n=== config 파일 경로 ===")
with tempfile.TemporaryDirectory() as d:
    cfg = os.path.join(d, "c.json")
    json.dump({"allowed_ranges": ["10.200.0.0/16"]}, open(cfg, "w"))
    code, out, r = run_main(["10.200.1.1", "--auto", "--no-save", "--config", cfg])
    check("config 허용대역 적용(바인딩 성공)", "10.200.0.0/16" in out)

print("\n=== 재개 (RECON 재사용) ===")
with tempfile.TemporaryDirectory() as d:
    run_main(["10.129.1.5", "--auto", "--state-dir", d])              # 1차 저장
    # 2차: nmap DOWN 반환해도 재스캔 안 함
    r2 = FakeRunner(lambda c: RunOutput(c, stdout="<nmaprun><host><status state='down'/></host></nmaprun>")
                    if c.startswith("nmap") else RunOutput(c, stdout="ok"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["10.129.1.5", "--auto", "--resume", "--state-dir", d], runner=r2)
    out = buf.getvalue()
    check("재개 종료 0", code == 0)
    check("재개 시 nmap 미호출", not any(c.startswith("nmap") for c in r2.calls))
    check("재개 안내 출력", "재개" in out)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
