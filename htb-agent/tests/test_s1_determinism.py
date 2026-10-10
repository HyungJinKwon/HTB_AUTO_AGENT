# 실행: htb-agent 디렉토리에서  python3 tests/test_s1_determinism.py
#
# S1 — 결정성: 성장 핑거프린트가 '웹앱 식별·vhost 등록'도 성장으로 인정해야 한다.
# 과거엔 이들만 자란 스윕이 '정체'로 오판돼 조기 종료 → 소비 스테이지가 영영 안 돌던 버그.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard                   # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput       # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope        # noqa: E402
from htb_agent.knowledge import KnowledgeBase                  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                         # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"
def mk_orc():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    o = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="")),
                     KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True)
    o._start = o._clock(); o._deadline = None
    o.world = WorldModel(target=T)
    return o

print("=== _world_fingerprint 가 웹/vhost 성장을 반영 ===")
orc = mk_orc()
rep = OrchestrationReport(target=T, flag_kind="boot2root")
fp0 = orc._world_fingerprint(rep)

# 1) 웹앱 제품 식별 → 성장으로 인정
orc.world.set_web_app("freepbx", "")
fp1 = orc._world_fingerprint(rep)
check("web_product 식별이 성장에 반영", fp1 != fp0)

# 2) 버전 보강 → 성장으로 인정
orc.world.set_web_app("freepbx", "16.0.40.7")
fp2 = orc._world_fingerprint(rep)
check("web_version 보강이 성장에 반영", fp2 != fp1)

# 3) vhost 등록 → 성장으로 인정
orc.hosts_map = {"connected.htb": T}
fp3 = orc._world_fingerprint(rep)
check("vhost 등록이 성장에 반영", fp3 != fp2)

# 4) 아무 변화 없으면 동일(멱등) — 조기종료 판정이 안정적
check("변화 없으면 동일 지문", orc._world_fingerprint(rep) == fp3)

print("\n=== 스테이지 메서드 존재/호출 가능(재배치 후 결선 확인) ===")
for m in ("_web_fingerprint_stage", "_version_probe_stage", "_exploit_lookup_stage"):
    check(f"{m} 존재", hasattr(orc, m) and callable(getattr(orc, m)))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
