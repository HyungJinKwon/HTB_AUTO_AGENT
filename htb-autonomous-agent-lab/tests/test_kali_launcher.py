# 실행: Kali에서 python3 tests/test_kali_launcher.py
import os
import subprocess
import sys
import tempfile

if os.name == "nt":
    print("Kali Bash launcher test skipped on Windows host")
    raise SystemExit(0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "scripts", "htb-kali.sh")

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def run(*args):
    return subprocess.run(["bash", LAUNCHER, *args], text=True, capture_output=True, cwd=ROOT)


print("=== Bash syntax ===")
for name in ("htb-kali.sh", "artex.sh", "pentestgpt.sh", "bloodhound_mcp.sh"):
    result = subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", name)], text=True,
                            capture_output=True)
    check(f"{name} syntax", result.returncode == 0)
help_result = subprocess.run(["bash", LAUNCHER, "--help"], text=True, capture_output=True)
check("--help은 설치 없이 성공", help_result.returncode == 0 and "Usage:" in help_result.stdout)

print("\n=== validate-only inputs ===")
with tempfile.TemporaryDirectory() as directory:
    profile = os.path.join(directory, "htb.ovpn")
    unsafe = os.path.join(directory, "unsafe.ovpn")
    with open(profile, "w", encoding="utf-8") as f:
        f.write("client\ndev tun\nremote lab.hackthebox.com 1337\n")
    with open(unsafe, "w", encoding="utf-8") as f:
        f.write("client\nup /tmp/not-safe\n")
    result = run(profile, "10.129.1.5", "--validate-only")
    check("정상 HTB profile/IP은 설치·VPN 없이 통과", result.returncode == 0 and "valid HTB" in result.stdout)
    result = run(profile, "192.0.2.10", "--validate-only")
    check("HTB 범위 밖 IP 거부", result.returncode == 2)
    result = run(unsafe, "10.129.1.5", "--validate-only")
    check("실행 hook 포함 VPN profile 거부", result.returncode == 2)
    result = run(profile, "10.129.1.5", "--domain", "corp.local", "--validate-only")
    check("사용자 없는 도메인 거부", result.returncode == 2)
    result = run(profile, "10.129.1.5", "--online-cve", "--no-one-day", "--validate-only")
    check("상충하는 1-day 옵션 거부", result.returncode == 2)

print(f"\n결과: {passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
