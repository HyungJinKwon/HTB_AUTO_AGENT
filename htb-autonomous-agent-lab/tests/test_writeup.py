# 실행: htb-agent 디렉토리에서  python3 tests/test_writeup.py
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.vuln import VulnKB
from htb_agent.orchestrator import Orchestrator
from htb_agent.writeup import generate_writeup

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/>
  <script id="vulners" output="CVE-2017-0144"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""

g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.10"); g.add_attacker_ip("10.10.14.5")
r = FakeRunner(lambda c: RunOutput(c, stdout=AD) if c.startswith("nmap") else RunOutput(c, stdout="share: data READ, WRITE"))
rep = Orchestrator(g, r, KnowledgeBase.load(), auto_approve_in_scope,
                   vuln_kb=VulnKB.load(), is_tool_available=lambda b: True).run()
rep.one_day_leads = [{
    "source": "searchsploit", "id": "12345", "title": "Example advisory",
    "url": "https://www.exploit-db.com/exploits/12345", "status": "unverified-lead",
}]

md = generate_writeup(rep, attacker_ip="10.10.14.5", machine_name="TestBox")

print("=== 구조/섹션 ===")
for sec in ["# TestBox", "## 0. 개요", "## 1. 정찰", "## 2. 열거", "## 3. 취약점 분석",
            "## 4. 공격 시나리오", "## 5. 초기 침투", "## 6. 권한 상승",
            "## 7. 블루팀 탐지 지표", "## 8. 마무리"]:
    check(f"섹션 존재: {sec}", sec in md)

print("\n=== 값 치환/플레이스홀더 ===")
check("타겟 IP 치환", "10.129.1.10" in md)
check("공격자 IP 치환", "10.10.14.5" in md)
check("유저 플레이스홀더 유지", "<유저명>" in md)
check("호스트명 플레이스홀더 유지", "<호스트명>" in md)

print("\n=== 포트표/명령해설 ===")
check("포트표 헤더", "| 포트 | 프로토콜 | 서비스 | 버전/배너 |" in md)
check("열린 포트 표기(445)", "| 445 |" in md)
check("3분할 해설(바이너리)", "바이너리 :" in md)

print("\n=== 취약점 ===")
check("CVE 추출 표기", "CVE-2017-0144" in md)
check("버전 매핑(vsftpd)", "vsftpd" in md.lower())
check("1-day 후보는 미검증 경계와 함께 기록", "Example advisory" in md and "미검증" in md)

print("\n=== 블루팀 지표(관측 포트 조건) ===")
check("Kerberos 지표(88 열림)", "4768" in md or "Kerberos" in md)
check("SMB 지표(445 열림)", "5140" in md or "SMB" in md)
check("Wireshark 필터", "Wireshark 필터" in md)
check("Snort/Suricata 룰", "Snort/Suricata" in md)

print("\n=== 순수 Markdown(HTML 태그 배제) ===")
check("HTML div 없음", "<div" not in md)
check("HTML table 없음", "<table" not in md.lower())
check("HTML br 없음", "<br" not in md.lower())

# ── Tistory 13섹션 템플릿 ──
from htb_agent.writeup import generate_tistory
print("\n=== Tistory 13섹션 ===")
mdt = generate_tistory(rep, attacker_ip="10.10.14.5", machine_name="TestBox")
for i in range(1, 14):
    check(f"섹션 {i} 존재", f"## {i}." in mdt)
check("아키텍처 다이어그램", "HTB VPN" in mdt and "```" in mdt)
check("내장 셸 매핑(Windows)", "whoami /all" in mdt)   # rep 는 Windows-AD
check("고급 조합(SMB)", "netexec smb" in mdt)
check("블루팀 지표", "Snort/Suricata" in mdt)
check("취약점 CVE", "CVE-2017-0144" in mdt)
check("순수 MD(HTML div 없음)", "<div" not in mdt)
print(f"\n(tistory) 누적 결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
