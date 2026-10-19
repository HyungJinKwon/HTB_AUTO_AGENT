# 실행: htb-agent 디렉토리에서  python3 tests/test_state.py
import sys, tempfile, os
sys.path.insert(0, "src")
from htb_agent.state import SessionState, StateStore, host_to_dict, host_from_dict
from htb_agent.observation.parsers import parse_nmap_xml
from htb_agent.observation.compressor import profile_from_nmap
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator
from htb_agent.target_profiler import OSClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2 Ubuntu"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""

print("=== 직렬화 왕복 ===")
st = SessionState(target="10.129.1.5", allowed_ranges=["10.129.0.0/16"],
                  attacker_ips=["10.10.14.5"], recon_status="success")
st.add_history("test event")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    path = store.save(st)
    check("저장 파일 생성", os.path.isfile(path))
    check("exists True", store.exists("10.129.1.5"))
    back = store.load("10.129.1.5")
    check("왕복 보존", back.target == "10.129.1.5" and back.attacker_ips == ["10.10.14.5"])
    check("이력 보존", len(back.history) == 1)
    check("파일명 안전화", os.path.basename(path) == "10.129.1.5.json")

print("\n=== host <-> dict 재구성 ===")
host = parse_nmap_xml(LINUX).first_host()
d = host_to_dict(host)
host2 = host_from_dict(d)
check("포트 재구성", set(host2.open_ports) == {22, 80})
check("배너 재구성", any("OpenSSH" in p.banner for p in host2.ports))
check("재구성 후 프로파일 동일", profile_from_nmap(host2).os_class == OSClass.LINUX)

print("\n=== 중단/재개 (RECON 재사용) ===")
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5")
    g.add_attacker_ip("10.10.14.5"); return g
def runner_ok(cmd):
    if cmd.startswith("nmap"): return RunOutput(cmd, stdout=LINUX)
    return RunOutput(cmd, stdout="ok")
ALL = lambda b: True

with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    # 1차 실행: 스캔 성공 + 상태 저장
    r1 = FakeRunner(runner_ok)
    Orchestrator(guard(), r1, KnowledgeBase.load(), auto_approve_in_scope,
                 state_store=store, is_tool_available=ALL).run()
    check("1차 후 상태 저장됨", store.exists("10.129.1.5"))
    saved = store.load("10.129.1.5")
    check("저장된 host 포트", set(p["port"] for p in saved.host["ports"]) == {22, 80})
    check("저장된 프로파일", saved.profile["os_class"] == "linux")

    # 2차 실행(재개): nmap 이 DOWN 반환해도 재스캔 안 함(저장 포트 재사용)
    r2 = FakeRunner(lambda c: RunOutput(c, stdout="<nmaprun><host><status state='down'/></host></nmaprun>")
                    if c.startswith("nmap") else RunOutput(c, stdout="ok"))
    rep = Orchestrator(guard(), r2, KnowledgeBase.load(), auto_approve_in_scope,
                       state_store=store, resume=True, is_tool_available=ALL).run()
    check("재개 시 nmap 재호출 안 함", not any(c.startswith("nmap") for c in r2.calls))
    check("재개 시 RECON 생략 표시", rep.recon is None)
    check("재개로도 done 도달", rep.status == "done")
    check("재개 enum 수행", len(rep.enum_findings) > 0)
    check("이력 누적(2건 이상)", len(store.load("10.129.1.5").history) >= 2)

print("\n=== 깨진 상태파일 내성 ===")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d); os.makedirs(d, exist_ok=True)
    with open(store.path_for("10.129.1.5"), "w") as f:
        f.write("{bad json")
    check("깨진 파일 load None", store.load("10.129.1.5") is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
