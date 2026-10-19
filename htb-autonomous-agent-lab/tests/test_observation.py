# 실행: htb-agent 디렉토리에서  python3 tests/test_observation.py
import sys
sys.path.insert(0, "src")
from htb_agent.observation.parsers import parse_nmap_xml, parse_nmap_text, parse_http
from htb_agent.observation.compressor import profile_from_nmap, recommend_followup
from htb_agent.target_profiler import OSClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX_XML = """<?xml version="1.0"?><nmaprun><host>
<status state="up" reason="syn-ack"/><address addr="10.129.1.5" addrtype="ipv4"/>
<ports>
 <port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu" extrainfo="Ubuntu Linux"/></port>
 <port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="Apache httpd" version="2.4.41"/></port>
</ports></host></nmaprun>"""

AD_XML = """<?xml version="1.0"?><nmaprun><host>
<status state="up"/><address addr="10.129.1.10"/>
<ports>
 <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
 <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
 <port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
 <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
 <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
</ports>
<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019 Standard 17763"/></hostscript>
</host></nmaprun>"""

DOWN_XML = """<?xml version="1.0"?><nmaprun><host>
<status state="down" reason="no-response"/><address addr="10.129.1.99"/></host></nmaprun>"""

print("=== nmap XML 파싱 ===")
r = parse_nmap_xml(LINUX_XML)
h = r.first_host()
check("호스트 up", h.state=="up")
check("열린포트 {22,80}", set(h.open_ports)=={22,80})
check("배너 파싱(OpenSSH)", any("OpenSSH" in p.banner for p in h.ports))
check("Linux 프로파일", profile_from_nmap(h).os_class==OSClass.LINUX)

r = parse_nmap_xml(AD_XML)
h = r.first_host()
check("AD 포트 파싱", {88,389,445}.issubset(set(h.open_ports)))
check("hostscript smb-os-discovery 추출", "smb-os-discovery" in h.hostscripts)
check("Windows-AD 프로파일", profile_from_nmap(h).os_class==OSClass.WINDOWS_AD)
check("DC 판정", profile_from_nmap(h).is_domain_controller)

print("\n=== host down → 폴백(-Pn) ===")
r = parse_nmap_xml(DOWN_XML)
check("다운 감지", r.seems_down and not r.any_up)
sugg = recommend_followup(r)
check("-Pn 폴백 제안", any("-Pn" in s for s in sugg))

print("\n=== nmap 텍스트 보조 파싱 ===")
txt = """Starting Nmap
Nmap scan report for 10.129.1.5
Host is up (0.012s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
"""
r = parse_nmap_text(txt)
check("텍스트 포트 파싱", set(r.first_host().open_ports)=={22,80})
down_txt = "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn"
check("텍스트 다운힌트", parse_nmap_text(down_txt).seems_down)

print("\n=== HTTP(curl -i) 파싱 ===")
resp = ("HTTP/1.1 301 Moved Permanently\r\n"
        "Server: nginx/1.18.0\r\n"
        "Location: http://machine.htb/\r\n"
        "Content-Length: 162\r\n\r\n"
        "<html><head><title>Redirecting</title></head></html>")
h = parse_http(resp)
check("상태코드 301", h.status==301)
check("Server 헤더", h.server=="nginx/1.18.0")
check("Location 추출", h.location=="http://machine.htb/")
check("title 추출", h.title=="Redirecting")
# 리다이렉트 체인 → 최종 응답 헤더만
chain = ("HTTP/1.1 301 Moved Permanently\r\nLocation: /app\r\n\r\n"
         "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Home</title>")
h = parse_http(chain)
check("체인 최종 상태 200", h.status==200)
check("체인 최종 Server", h.server=="Apache")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
