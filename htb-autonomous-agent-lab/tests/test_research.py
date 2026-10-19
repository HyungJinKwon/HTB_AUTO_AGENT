# 실행: htb-agent 디렉토리에서 python3 tests/test_research.py
import json
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")

from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator
from htb_agent.research import OneDayResearch, service_query
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def host(*ports):
    return SimpleNamespace(ports=list(ports))


def port(product, version):
    return SimpleNamespace(state="open", product=product, version=version)


print("=== query boundary ===")
check("관측 제품/버전 허용", service_query("Apache HTTP Server", "2.4.49") == "Apache HTTP Server 2.4.49")
check("타겟 IP 거부", service_query("Apache 10.129.1.5", "2.4.49") is None)
check("머신 풀이 키워드 거부", service_query("HTB walkthrough", "1.0") is None)
check("옵션 토큰 거부", service_query("--script", "1.0") is None)


print("\n=== SearchSploit is local metadata only ===")
calls = []


def local_run(argv, **kwargs):
    calls.append((argv, kwargs))
    return SimpleNamespace(returncode=0, stdout=json.dumps({
        "RESULTS_EXPLOIT": [{"EDB-ID": "12345", "Title": "Example advisory"}],
    }))


r = OneDayResearch(run=local_run, available=lambda: True)
leads = r.collect(host(port("Apache", "2.4.49")))
check("argv 실행, shell 문자열 미사용", calls[0][0] == ["searchsploit", "--json", "Apache", "2.4.49"])
check("타겟 식별자 미포함", all("10.129" not in arg for arg in calls[0][0]))
check("후보는 미검증으로 표시", leads[0]["status"] == "unverified-lead" and leads[0]["id"] == "12345")


print("\n=== CVE and bounded online NVD ===")
calls.clear()
r = OneDayResearch(run=local_run, available=lambda: True)
r.collect(host(), ["CVE-2021-41773"])
check("CVE는 명시 옵션으로 제한", calls[0][0] == ["searchsploit", "--json", "--cve", "2021-41773"])

online_queries = []


def fake_nvd(query):
    online_queries.append(query)
    return {"vulnerabilities": [
        {"cve": {"id": "CVE-2021-41773", "vulnStatus": "Analyzed",
                 "descriptions": [{"lang": "en", "value": "Example CVE"}]}},
        {"cve": {"id": "CVE-2020-0001", "vulnStatus": "Rejected",
                 "descriptions": [{"lang": "en", "value": "Ignore"}]}},
    ]}


r = OneDayResearch(online=True, fetch=fake_nvd, available=lambda: False)
leads = r.collect(host(port("Apache", "2.4.49"), port("nginx", "1.18")))
check("온라인 NVD는 첫 안전 질의 1회로 제한", online_queries == ["Apache 2.4.49"])
check("Rejected CVE 제외", len(leads) == 1 and leads[0]["id"] == "CVE-2021-41773")


print("\n=== orchestrator wiring ===")
XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports><port protocol="tcp" portid="21">
<state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
<script id="vulners" output="CVE-2011-2523"/></port></ports></host></nmaprun>"""
calls.clear()
research = OneDayResearch(run=local_run, available=lambda: True)
guard = ScopeGuard.from_cidr_strings()
guard.bind_target("10.129.1.5")
runner = FakeRunner(lambda command: RunOutput(command, stdout=XML)
                    if command.startswith("nmap") else RunOutput(command, stdout="ok"))
report = Orchestrator(guard, runner, KnowledgeBase.load(), auto_approve_in_scope,
                      is_tool_available=lambda binary: True,
                      one_day_research=research).run()
flat = [arg for argv, _kwargs in calls for arg in argv]
check("서비스와 관측 CVE 모두 검색", "vsftpd" in flat and "2011-2523" in flat)
check("리포트에 후보와 미검증 경계", report.one_day_leads and "1-day 후보" in report.summary())
check("검색 인자에 target IP 없음", "10.129.1.5" not in flat)

online_queries.clear()
research = OneDayResearch(online=True, fetch=fake_nvd, available=lambda: False)
Orchestrator(guard, runner, KnowledgeBase.load(), auto_approve_in_scope,
             is_tool_available=lambda binary: True,
             one_day_research=research).run()
check("관측된 CVE를 온라인 1-day 질의보다 우선", online_queries == ["CVE-2011-2523"])

print(f"\n결과: {passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
