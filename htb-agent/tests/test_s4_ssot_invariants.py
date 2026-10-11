# 실행: htb-agent 디렉토리에서  python3 tests/test_s4_ssot_invariants.py
#
# S4-4 — 상태원(SSOT) 일관성 불변식: 같은 사실이 여러 컨테이너에 중복 저장되는 구조에서,
# '쓰기 단일 경로'(S4-1 자격증명·S4-2 플래그)가 실제로 컨테이너 간 일관성을 지키는지
# 전체 run() 후 교차 검증한다. 과거 S4-2 의 발판 플래그 분기 같은 '한쪽만 갱신' 회귀를
# 구조적으로 잡는 가드. (읽기 소스 완전 일원화는 소비자가 서로 달라 고위험·저이득이라
# 하지 않는다 — 대신 이 불변식으로 분기를 차단한다.)
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard               # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput   # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope    # noqa: E402
from htb_agent.knowledge import KnowledgeBase              # noqa: E402
from htb_agent.creds import Credential, CredentialVault    # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                     # noqa: E402
from htb_agent.flag import FlagHit                         # noqa: E402
from htb_agent import provenance as _prov                  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"
XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""

def run_with_vault():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    vault = CredentialVault([Credential("svc", "pw", source="cli")])
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                                     else RunOutput(c, stdout="")),
                       KnowledgeBase.load(), auto_approve_in_scope,
                       vault=vault, flag_kind="boot2root",
                       is_tool_available=lambda b: True, quiet=True)
    return orc, orc.run()

print("=== 전체 run() 후 상태원 일관성 ===")
orc, rep = run_with_vault()
w = rep.world

# (1) 서비스: world.services 포트 == host.open_ports (set_profile 가 host 에서 파생)
world_ports = {s.port for s in w.services}
host_ports = set(rep.host.open_ports) if rep.host else set()
check("서비스 SSOT: world.services 포트 == host.open_ports", world_ports == host_ports)

# (2) 자격증명: vault 의 모든 자격이 world.creds 에 반영(S4-1 시드/왕복 경로)
world_creds = set(w.creds)
missing = [c.username for c in orc.vault.creds
           if not any(wc.startswith(c.username + ":") or wc == c.username for wc in world_creds)]
check("자격증명 SSOT: vault ⊆ world.creds", missing == [])

print("\n=== 플래그 단일 쓰기 불변식: report.flags ↔ world.flags ===")
# _record_flag 를 거친 모든 플래그는 양쪽에 함께 있어야 한다(S4-2 분기 차단).
orc2, rep2 = run_with_vault()
for k, v in (("user", "HTB{u}"), ("root", "HTB{r}")):
    p = _prov.FlagProvenance(k, v, "<발판 세션 직독>", "foothold", "exploit-derived", "r")
    orc2._record_flag(rep2, FlagHit(v, k, "발판"), p)
# 불변식: report.flags 의 모든 (kind,value) 가 world.flags 에 존재
report_pairs = {(f.kind, f.value) for f in rep2.flags}
world_pairs = set(rep2.world.flags.items())
check("플래그 SSOT: report.flags ⊆ world.flags", report_pairs <= world_pairs)
check("플래그 SSOT: world.flags ⊆ report.flags", world_pairs <= report_pairs)
check("발판 플래그가 goal_reached 에 반영", orc2._goal_reached(rep2) is True)

print("\n=== 음성: world-only 기록은 불변식을 깬다(가드가 실제로 작동함을 입증) ===")
# 일부러 world 에만 기록 → report 와 어긋남 → 불변식 위반 감지됨(가드가 민감함을 증명).
orc3, rep3 = run_with_vault()
rep3.world.add_flag("user", "HTB{only_world}")   # 우회(옛 버그 재현)
rp = {(f.kind, f.value) for f in rep3.flags}
wp = set(rep3.world.flags.items())
check("world-only 기록 → 불변식 위반이 탐지됨", not (wp <= rp))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
