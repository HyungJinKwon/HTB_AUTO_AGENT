# 실행: htb-agent 디렉토리에서  python3 tests/test_clues.py
import sys
sys.path.insert(0, "src")
from htb_agent.clues import ClueStore

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 추출: 종류별 ===")
c = ClueStore()
c.harvest("Nmap scan report for DC01.corp.htb (10.129.1.10)")
check("호스트명 .htb", "DC01.corp.htb" in c.kinds().get("host", []))

c2 = ClueStore()
c2.harvest("found username: svc_backup in LDAP")
check("사용자명 user: 패턴", "svc_backup" in c2.kinds().get("user", []))

c3 = ClueStore()
c3.harvest("interesting file /var/www/html/config.php and /home/bob/.ssh/id_rsa")
paths = c3.kinds().get("path", [])
check("config 경로", any("config.php" in p for p in paths))
check("id_rsa 경로", any("id_rsa" in p for p in paths))

c4 = ClueStore()
c4.harvest("Server: Apache/2.4.49 (Unix) OpenSSH 8.2p1")
sw = c4.kinds().get("software", [])
check("소프트웨어 버전 추출", any("Apache" in s for s in sw))

print("=== 해시 vs 플래그 구분 ===")
# 플래그 파일 맥락의 32hex 는 단서(hash)로 잡지 않는다
c5 = ClueStore()
c5.harvest("cat user.txt => b2f5ff47436671b6e533d8dc3614845d")
check("플래그 맥락 32hex 는 hash 아님", "b2f5ff47436671b6e533d8dc3614845d" not in c5.kinds().get("hash", []))
# 플래그 맥락이 아니면 해시로 잡는다
c6 = ClueStore()
c6.harvest("NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
check("일반 맥락 해시 추출", bool(c6.kinds().get("hash")))

print("=== 중복제거 / 상한 / 누적 ===")
c7 = ClueStore()
check("새 단서 추가 True", c7.add("user", "admin"))
check("중복은 False", not c7.add("user", "admin"))
check("빈 값 False", not c7.add("user", "  "))
c8 = ClueStore(per_kind_cap=2)
c8.add("user", "a"); c8.add("user", "b")
check("상한 초과 거부", not c8.add("user", "c"))
# harvest 반환값 = 새로 추가된 수
c9 = ClueStore()
n1 = c9.harvest("user: alice\nuser: bob")
n2 = c9.harvest("user: alice")          # 중복
check("harvest 새 단서 수 반환", n1 == 2 and n2 == 0)

print("=== 컨텍스트 렌더 ===")
c10 = ClueStore()
c10.harvest("DC01.corp.htb user: alice /etc/backup.conf")
lines = c10.context_lines()
check("종류별 한 줄", any(l.startswith("host:") for l in lines))
check("truthy 판정", bool(c10))
check("빈 store 는 falsy", not ClueStore())

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
