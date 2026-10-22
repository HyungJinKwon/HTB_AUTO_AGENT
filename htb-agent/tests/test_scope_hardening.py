# 실행: htb-agent 디렉토리에서  python3 tests/test_scope_hardening.py
# H-1: 가드가 해석하지 못하는 주소 표기는 '확인 필요'로 올린다(fail-closed).
#      정상 명령의 숫자 인자(포트·스레드·타임아웃 등)는 오탐하지 않는다.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard, IPClass, decode_ipv4_literal
from htb_agent.command_validator import validate
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T, ATK = "10.129.1.5", "10.10.14.5"
HOSTS = {"machine.htb": T}
g = ScopeGuard.from_cidr_strings(); g.bind_target(T); g.add_attacker_ip(ATK)
def res(cmd): return g.inspect_command(cmd, hosts_map=HOSTS)
def auto(cmd): return res(cmd).auto_allowed

print("=== decode_ipv4_literal (inet_aton 규칙) ===")
check("정규 점4자리는 그대로", decode_ipv4_literal(T) == T)
check("단일 10진 정수", decode_ipv4_literal("167772161") == "10.0.0.1")
check("단일 16진", decode_ipv4_literal("0x0a000001") == "10.0.0.1")
check("8진 파트", decode_ipv4_literal("012.0.0.1") == "10.0.0.1")
check("2파트 축약(a.b)", decode_ipv4_literal("10.1") == "10.0.0.1")
check("3파트 축약(a.b.c)", decode_ipv4_literal("10.0.1") == "10.0.0.1")
check("범위 초과 → None", decode_ipv4_literal("4294967296") is None)
check("파트 초과(>255) → None", decode_ipv4_literal("256.1.1.1") is None)
check("잘못된 8진(09) → None", decode_ipv4_literal("09.1.1.1") is None)
check("호스트명 → None", decode_ipv4_literal("machine.htb") is None)
check("빈 0x → None", decode_ipv4_literal("0x") is None)

print("\n=== 비정규 숫자형 표기 → 확인 필요 ===")
r = res("curl 167772161")
check("네트워크 도구 bare 정수 호스트 → 확인 필요", not r.auto_allowed)
check("해석 결과를 사유에 표기", any("10.0.0.1" in x for x in r.needs_confirmation))
check("16진 bare 호스트 → 확인 필요", not auto("nc 0x0a000001 80"))
check("축약형 위치인자 → 확인 필요", not auto("ping -c 1 10.1"))
check("user@ 뒤 비정규 표기 → 확인 필요", not auto("ssh root@167772161"))
check("host:port 의 비정규 표기 → 확인 필요", not auto("openssl s_client -connect 0x0a000001:443"))
check("--opt=값 의 비정규 표기 → 확인 필요", not auto("nmap --exclude=167772161 " + T))
check("URL 숫자형 호스트 → 확인 필요", not auto("curl http://167772161/"))
check("sudo/proxychains 래퍼 뒤도 검사", not auto("sudo proxychains curl 167772161"))
check("파이프 뒤 구간도 검사", not auto("echo hi | nc 167772161 80"))
check("앞자리 0 점4자리(8진 해석) → 확인 필요", not auto("curl http://012.129.1.5/"))
# 타겟을 비정규 표기로 써도 통과시키지 않는다(정상 도구 사용엔 불필요한 표기)
tgt_int = str(int.from_bytes(bytes(int(x) for x in T.split(".")), "big"))
r = res("curl " + tgt_int)
check("타겟의 비정규 표기도 확인 필요(fail-closed)", not r.auto_allowed)
check("분류 정보는 TARGET 으로 남김", any(c == IPClass.TARGET for _, c, _ in r.classified))

print("\n=== IPv6 리터럴 ===")
check("IPv6 브래킷 URL → 확인 필요", not auto("curl http://[2001:db8::1]/"))
check("IPv6 bare(네트워크 도구) → 확인 필요", not auto("nc 2001:db8::1 80"))
check("IPv6 loopback ::1 → 허용", auto("curl http://[::1]:8000/"))
check("MAC 주소 형태는 IPv6 아님(오탐 없음)", auto("ping -c 1 " + T + " # aa:bb:cc:dd:ee:ff"))

print("\n=== 비-HTTP 스킴 호스트 분류 ===")
check("ldap:// 외부 호스트 → 확인 필요", not auto("ldapsearch -x -H ldap://evil.example.com -b dc=x"))
check("ldap:// 해석된 vhost → 자동허용", auto("ldapsearch -x -H ldap://machine.htb -b dc=x"))
check("mongodb:// 타겟 IP → 자동허용", auto(f"mongosh mongodb://{T}:27017"))
check("file:/// 는 호스트 아님", auto("curl file:///etc/hosts"))

print("\n=== 오탐 없음(정상 숫자 인자) ===")
SAFE = [
    "nc -lvnp 4444",
    f"nmap -p 1-65535 --min-rate 5000 -T4 {T}",
    f"curl -m 2.5 --connect-timeout 1.5 http://{T}/",
    f"hydra -t 4 -l admin -P /usr/share/wordlists/rockyou.txt ssh://{T}",
    f"ssh -p 2222 user@{T}",
    f"openssl s_client -connect {T}:443",
    "head -c 20000000 big.txt",
    "python3 -c 'print(hex(0x0a000001))'",
    f"timeout 30 curl http://{T}/",
    f"nc {ATK} 9001",
    f"ffuf -u http://{T}/FUZZ -w list.txt -t 50 -fs 1234",
]
for c in SAFE:
    check(f"자동허용 유지: {c[:52]}", auto(c))

# OID 의 점4자리 부분(1.3.6.1)은 기존 보수 규칙(test_scope 6번)대로 확인 대상 — 이번
# 숫자형 검사가 추가 사유를 만들지 않는지만 본다.
nc = res(f"snmpwalk -v2c -c public {T} 1.3.6.1.2.1.1").needs_confirmation
check("OID 에 비정규 표기 사유 추가 없음", not any("→" in x for x in nc))

print("\n=== 파일명 오탐: 비-TLD 확장자 파일은 호스트로 보지 않음 ===")
for c in ["head -c 20000000 big.bin", "strings a.out", "sqlite3 users.db .dump", "file chall.elf",
          "tshark -r cap.pcap", "john hash.hashes", "keepass2john vault.kdbx",
          f"certipy auth -pfx administrator.pfx -dc-ip {T}"]:
    check(f"파일 인자 자동허용: {c[:44]}", auto(c))
print("\n=== 확장자 목록 안전장치: 실제 TLD 호스트는 계속 확인 필요 ===")
# 실제 TLD(IANA) — 파일 확장자처럼 보여도 제외 목록에 넣으면 fail-open 이 되므로 넣지 않았다
for host in ["evil.pub", "evil.rs", "evil.pl", "evil.mov", "evil.cab", "evil.java"]:
    check(f"bare 호스트 확인 필요: curl {host}", not auto(f"curl {host}"))
check("URL 호스트는 확장자와 무관하게 분류(evil.bin)", not auto("curl http://evil.bin/"))

print("\n=== TLD 겹침 확장자(md·py·sh·so·zip): 네트워크 도구 호스트 위치면 호스트로 ===")
for c in ["curl evil.sh", "wget evil.zip", "nc evil.so 80", "ssh user@evil.py", "ping -c 1 evil.md",
          "sudo curl evil.sh"]:
    check(f"확인 필요: {c}", not auto(c))
for c in ["python3 exploit.py", "bash linpeas.sh", "cat notes.md", "unzip a.zip",
          f"scp exploit.py user@{T}:/tmp",                 # scp: ':' 없는 인자는 로컬 파일
          f"rsync -av ./tools.sh user@{T}:/tmp/",
          f"nc {T} 4444 < shell.sh",                       # 리다이렉트 대상은 파일
          f"ssh user@{T} python3 x.py",                    # ssh: 첫 위치 인자 뒤는 원격 명령
          f"ssh user@{T} 'bash -s' < enum.sh",
          f"curl -o out.zip http://{T}/a.zip"]:            # 옵션 값은 위치 인자 아님
    check(f"자동허용 유지: {c[:46]}", auto(c))
check("scp 원격 지정의 TLD 겹침 호스트는 확인 필요", not auto("scp a.txt user@evil.sh:/tmp"))
check("ssh 첫 위치 인자의 비정규 숫자 표기는 계속 검사", not auto("ssh 167772161 id"))

print("\n=== 승인 연동: 무프롬프트 모드에서 실행 안 됨 ===")
c = "curl 167772161"
check("auto/autonomous 승인자 거부", auto_approve_in_scope(c, validate(c), res(c)) is False)

print("\n=== 불변식: 동봉 KB 제안은 비정규 표기/IPv6 사유로 걸리지 않음 ===")
kb = KnowledgeBase.load("knowledge")
bad = []
total = 0
for rule in kb.rules:
    for tmpl in rule.suggest:
        cmd = (tmpl.replace("{t}", T).replace("{atk}", ATK).replace("{domain}", "machine.htb")
               .replace("{user}", "svc").replace("{pass}", "Passw0rd"))
        total += 1
        nc = res(cmd).needs_confirmation
        if any("→" in x or "(IPv6)" in x for x in nc):
            bad.append((cmd, nc))
check(f"KB 제안 {total}건 중 신규 사유 0건", not bad)
for cmd, nc in bad[:5]:
    print("     ↳", cmd[:90], nc)

print("\n=== vhost 퍼징(FUZZ.<도메인>) — 부모 도메인 스코프로 판정 ===")
# ffuf/wfuzz vhost 브루트는 'Host: FUZZ.<도메인>' 이 필수. 부모가 in-scope(hosts_map 등록
# vhost)면 서브도메인 퍼징은 in-scope 로 허용되어야 한다(과거엔 FUZZ.<도메인> 이 미해석 →
# 자동승인 거부 → vhost 브루트가 아예 안 돌았다).
ok_fuzz = auto('ffuf -w w.txt -u http://10.129.1.5/ -H "Host: FUZZ.machine.htb" -ac')
check("FUZZ.<in-scope 도메인> 은 자동허용(서브도메인 퍼징)", ok_fuzz)
# 보안: 부모가 범위 밖이면 FUZZ 라도 허용 금지(대상 통제 리다이렉트/헤더로 스코프 우회 차단).
bad_fuzz = auto('ffuf -w w.txt -u http://10.129.1.5/ -H "Host: FUZZ.evil.com" -ac')
check("FUZZ.<외부 도메인> 은 여전히 거부(우회 아님)", not bad_fuzz)
# 보안: FUZZ 가 아닌 미등록 서브도메인은 종전대로 확인 필요(일반 경로 불변 — FUZZ 만 특례)
check("비-FUZZ 미등록 서브도메인은 종전대로 확인 필요",
      not auto("curl -s http://other.machine.htb/"))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
