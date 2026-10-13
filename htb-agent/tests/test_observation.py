# 실행: htb-agent 디렉토리에서  python3 tests/test_observation.py
import sys
sys.path.insert(0, "src")
from htb_agent.observation.parsers import parse_nmap_xml, parse_nmap_text, parse_http
from htb_agent.observation.compressor import profile_from_nmap
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

print("\n=== host down 감지 ===")
r = parse_nmap_xml(DOWN_XML)
check("다운 감지", r.seems_down and not r.any_up)

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

print("\n=== HTTP 심화 파싱 (쿠키·보안헤더·폼·generator) ===")
RICH = ("HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.49\r\n"
        "Set-Cookie: SID=abc; Path=/; HttpOnly\r\n"
        "Set-Cookie: track=xyz; Secure; SameSite=Lax\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Powered-By: PHP/7.4\r\n\r\n"
        '<html><head><title> Admin </title>'
        '<meta name="generator" content="WordPress 5.8"></head><body>'
        '<form method="post" action="/login">'
        '<input name="user"><input type="password" name="pw"></form></body></html>')
h = parse_http(RICH)
check("쿠키 2개 수집(중복 Set-Cookie)", len(h.cookies) == 2)
check("쿠키 플래그 파싱", any(c.name == "SID" and c.httponly and not c.secure for c in h.cookies))
check("로그인폼 탐지", h.has_login_form and h.forms[0].method == "post")
check("폼 action", h.forms[0].action == "/login")
check("generator(CMS) 추출", h.generator == "WordPress 5.8")
check("보안헤더 present(X-Frame-Options)", "X-Frame-Options" in h.present_security_headers)
check("보안헤더 missing(CSP/HSTS)", {"CSP", "HSTS"} <= set(h.missing_security_headers))
check("summary 에 누락헤더/쿠키/폼", all(x in h.summary()
      for x in ("보안헤더 누락", "cookies=", "forms=", "generator=")))
# 폼/쿠키 없는 단순 응답은 조용히(회귀)
simple = parse_http("HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n<h1>nope</h1>")
check("단순 응답: 쿠키/폼 없음", not simple.cookies and not simple.forms and not simple.has_login_form)
check("단순 응답: 모든 보안헤더 누락 표기", len(simple.missing_security_headers) == 6)

# 앱 버전 능동 추출: 본문에 '앱이름 버전'이 있으면 뽑고, 라이브러리 버전은 오탐 안 함
hv = parse_http("HTTP/1.1 200 OK\r\n\r\n<title>FreePBX Administration</title>"
                "<div class=footer>FreePBX 16.0.40 licensed</div>")
check("앱 버전 추출(FreePBX 16.0.40)", hv.app_version == "FreePBX 16.0.40")
check("summary 에 appver 노출", "appver=FreePBX 16.0.40" in hv.summary())
hn = parse_http("HTTP/1.1 200 OK\r\n\r\n<title>FreePBX Administration</title>"
                "<link href='assets/css/bootstrap-3.3.7.min.css'>")
check("라이브러리 버전은 오탐 안 함(app_version 빈값)", hn.app_version == "")

print("\n=== 파서 내구성(fail-closed): 비정수 portid 는 해당 포트만 skip ===")
# 변형 XML 의 portid 가 비정수여도 int() 예외로 전체 파싱이 크래시하면 안 됨(2.31 가드).
BAD_XML = ("""<?xml version="1.0"?><nmaprun><host><status state="up"/>"""
           """<address addr="10.129.1.9" addrtype="ipv4"/><ports>"""
           """<port protocol="tcp" portid=""><state state="open"/><service name="x"/></port>"""
           """<port protocol="tcp" portid="abc"><state state="open"/><service name="y"/></port>"""
           """<port protocol="tcp" portid="80"><state state="open"/>"""
           """<service name="http" product="Apache"/></port></ports></host></nmaprun>""")
bh = parse_nmap_xml(BAD_XML).first_host()
check("비정수 portid 여도 크래시 없이 파싱", bh is not None)
check("유효 포트(80)는 살아남음", 80 in [p.port for p in bh.ports])
check("불량 포트는 버려짐(유효분만)", [p.port for p in bh.ports] == [80])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
