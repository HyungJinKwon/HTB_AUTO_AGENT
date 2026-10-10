# 실행: htb-agent 디렉토리에서  python3 tests/test_s4_cred_roundtrip.py
#
# S4 — 자격증명 상태원 왕복(SSOT): _persist 가 st.credentials 를 쓰기만 하고 _restore 가
# 되읽지 않아 '재개 세션이 수확한 자격증명을 통째로 잃던' 비대칭을 교정했다. 이를 고정한다.
import sys, os, tempfile
sys.path.insert(0, "src")
from htb_agent.creds import Credential, CredentialVault          # noqa: E402
from htb_agent.state import SessionState, StateStore             # noqa: E402
from htb_agent.scope_guard import ScopeGuard                      # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput          # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope           # noqa: E402
from htb_agent.knowledge import KnowledgeBase                     # noqa: E402
from htb_agent.orchestrator import Orchestrator                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== CredentialVault.from_list — to_list 의 역(왕복·중복제거) ===")
v = CredentialVault([Credential("admin", "pw", nt_hash=None, source="cli")])
dumped = v.to_list()
v2 = CredentialVault()
added = v2.from_list(dumped)
check("왕복: 1건 복원", added == 1 and len(v2.creds) == 1)
check("필드 보존", v2.creds[0].username == "admin" and v2.creds[0].password == "pw")
# 기존과 동일 자격증명은 중복 제거
again = v2.from_list(dumped)
check("중복 복원은 0건", again == 0 and len(v2.creds) == 1)
# None/빈 입력 내성
check("None 입력 내성", CredentialVault().from_list(None) == 0)
check("username 없는 dict 무시", CredentialVault().from_list([{"password": "x"}]) == 0)

print("\n=== 재개(resume) 시 자격증명이 볼트+월드로 복원 ===")
T = "10.129.1.5"
XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T); return g
ALL = lambda b: True

with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    # 1차: 스캔 + 상태 저장. 볼트에 자격증명을 넣어두고 저장(=수확된 자격증명 모사).
    vault1 = CredentialVault([Credential("svc", "S3cret!", domain="htb", source="harvest")])
    r1 = FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                    else RunOutput(c, stdout="ok"))
    Orchestrator(guard(), r1, KnowledgeBase.load(), auto_approve_in_scope,
                 vault=vault1, state_store=store, is_tool_available=ALL).run()
    saved = store.load(T)
    check("저장된 state 에 자격증명 있음",
          bool(saved.credentials) and saved.credentials[0]["username"] == "svc")

    # 2차(재개): 빈 볼트로 시작해도 저장된 자격증명이 볼트·월드로 복원돼야 한다.
    vault2 = CredentialVault()   # 비어서 시작 — CLI 자격증명 없음
    orc2 = Orchestrator(guard(), r1, KnowledgeBase.load(), auto_approve_in_scope,
                        vault=vault2, state_store=store, resume=True, is_tool_available=ALL)
    orc2.run()
    check("재개: 볼트에 자격증명 복원", any(c.username == "svc" for c in orc2.vault.creds))
    check("재개: 볼트 비밀/도메인 보존",
          any(c.password == "S3cret!" and c.domain == "htb" for c in orc2.vault.creds))
    check("재개: 월드에도 자격증명 반영(user:pass)",
          any(wc.startswith("svc:") for wc in (orc2.world.creds if orc2.world else [])))
    # 월드에 자격증명이 있으면 권한레벨이 최소 credentialed 로 올라간다(add_cred 효과).
    check("재개: 권한레벨 credentialed 승격",
          orc2.world is not None and orc2.world.has_access("credentialed"))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
