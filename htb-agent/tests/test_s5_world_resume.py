# 실행: htb-agent 디렉토리에서  python3 tests/test_s5_world_resume.py
#
# S5-3 — 월드 식별 상태·해시 resume 왕복: 재개 시 raw_output(비영속)이 없어 핑거프린트가
# '손실 요약'으로 퇴행(S0 교정 무력화)하고 수집 해시가 사라지던 결함 교정을 고정한다.
import sys, tempfile
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard               # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput   # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope    # noqa: E402
from htb_agent.knowledge import KnowledgeBase              # noqa: E402
from htb_agent.state import SessionState, StateStore        # noqa: E402
from htb_agent.orchestrator import Orchestrator            # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"
XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
ALL = lambda b: True

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T); return g

print("=== _persist 가 월드 제품/버전·해시를 저장 ===")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    o1 = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                                          else RunOutput(c, stdout="")),
                      KnowledgeBase.load(), auto_approve_in_scope,
                      state_store=store, is_tool_available=ALL, quiet=True)
    rep1 = o1.run()
    # 직전 실행의 월드에 제품/버전·해시가 있다고 가정(엔진 외부 경로로 확정된 상태 모사)
    o1.world.set_web_app("freepbx", "16.0.40.7")
    o1._found_hashes.append("$1$abc$0123456789abcdef0123456./")
    # run() 종료 시 _persist 가 호출됐지만 위 수동 상태 설정은 그 이후다 → 직접 _persist 로 저장
    o1._persist(rep1, store.load(T))
    saved = store.load(T)
    check("state.web_product 저장", saved.web_product == "freepbx")
    check("state.web_version 저장", saved.web_version == "16.0.40.7")
    check("state.found_hashes 저장", any("$1$abc$" in h for h in saved.found_hashes))

print("\n=== 재개(resume): 월드 제품/버전·해시 복원(요약 재파싱 의존 없이) ===")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    # 1차 저장 상태를 직접 구성(host 있어 RECON 재사용 경로 — 재개 트리거)
    from htb_agent.state import host_to_dict
    from htb_agent.observation.parsers import parse_nmap_xml
    host = parse_nmap_xml(XML).first_host()
    st = SessionState(target=T, host=host_to_dict(host), recon_status="success",
                      web_product="freepbx", web_version="16.0.40.7",
                      found_hashes=["$1$abc$0123456789abcdef0123456./"])
    store.save(st)
    o2 = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="")),
                      KnowledgeBase.load(), auto_approve_in_scope,
                      state_store=store, resume=True, is_tool_available=ALL, quiet=True)
    o2.run()
    check("재개: world.web_product 복원", o2.world is not None and o2.world.web_product == "freepbx")
    check("재개: world.web_version 복원(요약 손실 없이)",
          o2.world is not None and o2.world.web_version == "16.0.40.7")
    check("재개: 수집 해시 복원", any("$1$abc$" in h for h in o2._found_hashes))

print("\n=== 2.31: hosts_map/learned/access_level resume 왕복 ===")
# 자동 등록 vhost·학습 토픽·권한레벨이 재개 시 비영속으로 퇴행하던 결손(MED-1/LOW-1/LOW-2) 교정 고정.
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    o3 = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                                          else RunOutput(c, stdout="")),
                      KnowledgeBase.load(), auto_approve_in_scope,
                      state_store=store, is_tool_available=ALL, quiet=True)
    rep3 = o3.run()
    # 엔진 외부 경로로 확정된 상태 모사: 자동 vhost 등록 + 학습 + 권한상승
    o3.hosts_map = {"blog.target.htb": T}
    o3._vhost_seen.add("blog.target.htb")
    o3.world.add_learned("freepbx-rce")
    o3.world.raise_access("root")
    o3._persist(rep3, store.load(T))
    saved3 = store.load(T)
    check("state.hosts_map 저장", saved3.hosts_map.get("blog.target.htb") == T)
    check("state.learned 저장", "freepbx-rce" in saved3.learned)
    check("state.access_level 저장", saved3.access_level == "root")

with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    from htb_agent.state import host_to_dict as _h2d
    from htb_agent.observation.parsers import parse_nmap_xml as _pnx
    host3 = _pnx(XML).first_host()
    st3 = SessionState(target=T, host=_h2d(host3), recon_status="success",
                       hosts_map={"blog.target.htb": T}, learned=["freepbx-rce"],
                       access_level="root")
    store.save(st3)
    o4 = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="")),
                      KnowledgeBase.load(), auto_approve_in_scope,
                      state_store=store, resume=True, is_tool_available=ALL, quiet=True)
    o4.run()
    check("재개: hosts_map 복원(vhost 스코프)", (o4.hosts_map or {}).get("blog.target.htb") == T)
    check("재개: _vhost_seen 복원(재등록 억제)", "blog.target.htb" in o4._vhost_seen)
    check("재개: world.learned 복원", o4.world is not None and "freepbx-rce" in o4.world.learned)
    check("재개: world.access_level 복원", o4.world is not None and o4.world.access_level == "root")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
