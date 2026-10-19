# 실행: htb-agent 디렉토리에서  python3 tests/test_net_parsers.py
import sys
sys.path.insert(0, "src")
from htb_agent.observation.net import parse_dig, parse_snmpwalk
from htb_agent.observation.summarize import summarize_tool_output

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== dig ===")
dig = """; <<>> DiG 9.16 <<>> axfr machine.htb
machine.htb.		604800	IN	SOA	ns.machine.htb. root.machine.htb. 2 604800 86400
machine.htb.		604800	IN	NS	ns.machine.htb.
machine.htb.		604800	IN	A	10.129.1.5
admin.machine.htb.	604800	IN	A	10.129.1.6
mail		604800	IN	MX	10 mail.machine.htb.
"""
r = parse_dig(dig)
check("레코드 파싱(5건)", len(r.records) == 5)
check("A 레코드", any(x.rtype == "A" and x.value == "10.129.1.5" for x in r.records))
check("서브도메인 A", any(x.name == "admin.machine.htb" for x in r.records))
check("주석 라인 제외", all(not x.name.startswith(";") for x in r.records))

print("\n=== snmpwalk ===")
snmp = """SNMPv2-MIB::sysDescr.0 = STRING: Linux machine 5.4.0 x86_64
SNMPv2-MIB::sysName.0 = STRING: machine
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "systemd"
iso.3.6.1.2.1.25.4.2.1.2.2 = STRING: "sshd"
"""
r = parse_snmpwalk(snmp)
check("OID 4건", len(r.entries) == 4)
check("sysDescr 추출", "Linux machine" in r.sysdescr)
check("값 따옴표 제거", any(v == "systemd" for _, v in r.entries))

print("\n=== summarize 디스패처 ===")
check("dig 라우팅", "dns:" in summarize_tool_output("dig axfr @10.129.1.5 machine.htb", dig))
check("snmpwalk 라우팅", "snmp:" in summarize_tool_output("snmpwalk -v2c -c public 10.129.1.5", snmp))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
