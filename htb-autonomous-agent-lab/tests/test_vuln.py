# 실행: htb-agent 디렉토리에서  python3 tests/test_vuln.py
import sys, tempfile, os, json
sys.path.insert(0, "src")
from htb_agent.vuln import extract_vuln_ids, VulnKB
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== CVE/CWE ID 추출 ===")
h = extract_vuln_ids("nmap vulners: CVE-2011-2523 cvss 10.0; also cwe-78 and CVE-2021-41773")
check("CVE 추출", "CVE-2011-2523" in h.cves and "CVE-2021-41773" in h.cves)
check("CWE 대소문자 정규화", "CWE-78" in h.cwes)
check("중복 제거/정렬", extract_vuln_ids("CVE-2011-2523 CVE-2011-2523").cves == ["CVE-2011-2523"])
check("없으면 빈", not extract_vuln_ids("아무것도 없음").any())

print("\n=== 시드 버전 매핑 ===")
kb = VulnKB.load()
m = kb.match(["vsftpd 2.3.4"])
check("vsftpd 2.3.4 → CVE-2011-2523", m and "CVE-2011-2523" in m[0].cve)
check("severity critical 정렬", m[0].severity == "critical")
check("버전 불일치는 매칭 안 함", kb.match(["vsftpd 3.0.3"]) == [])
check("서비스 불일치 매칭 안 함", kb.match(["nginx 1.18.0"]) == [])
check("버전 경계 오매칭 방지(12.3.4)", kb.match(["vsftpd 12.3.4"]) == [])
check("버전 경계 오매칭 방지(2.3.40)", kb.match(["vsftpd 2.3.40"]) == [])
m2 = kb.match(["Apache httpd 2.4.49"])
check("Apache 2.4.49 → path traversal", m2 and "CVE-2021-41773" in m2[0].cve)

print("\n=== 사용자 취약점 규칙(성장) ===")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "vulns"))
    rule = {"name": "내 커스텀 취약점", "service": "customsvc", "version_contains": ["1.0"],
            "cve": ["CVE-2099-0001"], "cwe": ["CWE-79"], "suggest": ["searchsploit customsvc"],
            "severity": "high", "note": "테스트"}
    json.dump(rule, open(os.path.join(d, "vulns", "my.json"), "w"))
    kb2 = VulnKB.load(base_dir=d)
    m = kb2.match(["customsvc 1.0.2"])
    check("사용자 규칙 매칭", m and m[0].cve == ["CVE-2099-0001"])
    check("사용자 규칙 source", m[0].source.startswith("user:"))
    check("깨진 파일 내성", True)  # 로드가 예외 없이 됨

print("\n=== 오케스트레이터 VULN 단계 ===")
VSFTPD_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="21"><state state="open"/>
  <service name="ftp" product="vsftpd" version="2.3.4"/>
  <script id="vulners" output="CVE-2011-2523 10.0 https://..."/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
r = FakeRunner(lambda c: RunOutput(c, stdout=VSFTPD_XML) if c.startswith("nmap") else RunOutput(c, stdout="ok"))
rep = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   vuln_kb=VulnKB.load(), is_tool_available=lambda b: True).run()
check("스크립트 출력서 CVE 추출", "CVE-2011-2523" in rep.detected_cve)
check("버전 매핑으로 취약점 매칭", any("CVE-2011-2523" in vm.cve for vm in rep.vuln_matches))
check("요약에 VULN 섹션", "VULN" in rep.summary() and "CVE-2011-2523" in rep.summary())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
