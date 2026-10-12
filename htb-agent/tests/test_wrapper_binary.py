# 실행: htb-agent 디렉토리에서  python3 tests/test_wrapper_binary.py
#
# util.binary_of/binary_index 의 래퍼(sudo/nice/proxychains…) 건너뛰기 — 값 받는 옵션의 값
# 토큰까지 올바르게 소비해 '실제 도구'를 집는지(감사 B-MED2). 값 안 받는 boolean 옵션은
# 값 토큰을 소비하지 않아야 한다(sudo -n vs nice -n 의 의미 차이).
import sys

sys.path.insert(0, "src")
from htb_agent.util import binary_index, binary_of  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


W = dict(strip_path=True, skip_wrappers=True)

print("=== 값 받는 래퍼 옵션의 값 토큰까지 건너뜀 ===")
check("sudo -u www-data cat → cat", binary_of("sudo -u www-data cat /root/x", **W) == "cat")
check("nice -n 10 nmap → nmap", binary_of("nice -n 10 nmap 10.0.0.1", **W) == "nmap")
check("ionice -c 2 -n 0 curl → curl", binary_of("ionice -c 2 -n 0 curl http://t", **W) == "curl")
check("proxychains -f cfg nmap → nmap", binary_of("proxychains -f my.conf nmap t", **W) == "nmap")

print("\n=== boolean 옵션은 값 토큰을 소비하지 않음(의미 차이) ===")
# sudo -n = 비대화(boolean) — 다음 토큰은 도구다. nice -n 과 달라 래퍼별 분리가 핵심.
check("sudo -n cat → cat(값 소비 안 함)", binary_of("sudo -n cat /etc/passwd", **W) == "cat")
check("proxychains -q nmap → nmap(-q boolean)", binary_of("proxychains -q nmap t", **W) == "nmap")

print("\n=== 단순 래퍼·중첩·비래퍼 ===")
check("sudo cat → cat", binary_of("sudo cat /root/x", **W) == "cat")
check("sudo nmap → nmap", binary_of("sudo nmap -sV t", **W) == "nmap")
check("env 할당 선행 + 래퍼", binary_of("FOO=bar sudo -u u nmap t", **W) == "nmap")
check("래퍼 없는 평범한 명령", binary_of("nmap -Pn t", **W) == "nmap")
check("skip_wrappers=False 면 sudo 그대로", binary_of("sudo nmap t", strip_path=True) == "sudo")

print("\n=== binary_index(_insert_flag 용) 도 동일 규칙 ===")
toks = "sudo -u www-data nmap 10.0.0.1".split()
check("sudo -u www-data nmap → index 3(nmap)", binary_index(toks) == 3 and toks[3] == "nmap")
toks2 = "nice -n 10 curl x".split()
check("nice -n 10 curl → index 3(curl)", binary_index(toks2) == 3 and toks2[3] == "curl")
check("빈 토큰 → len", binary_index([]) == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
