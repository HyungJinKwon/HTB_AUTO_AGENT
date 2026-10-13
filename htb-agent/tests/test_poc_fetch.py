# 실행: htb-agent 디렉토리에서  python3 tests/test_poc_fetch.py
#
# 공개 PoC 자동 조달(Commit 7, 옵트인): 레지스트리 선언 출처에서만 받고, 받기만 하며(실행은 3관문),
# ASSASSIN_NO_NET 이면 실 네트워크 조달을 차단한다. 실제 git/네트워크 없이 주입 fetch_fn 으로 검증.
import os
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent import exploit_modules as em              # noqa: E402
from htb_agent import poc_fetch                          # noqa: E402
from htb_agent.knowledge import KnowledgeBase            # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard             # noqa: E402
from htb_agent.tools.recon import auto_approve_contained  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.245.100"
MOD = em.match("freepbx", "16.0.40.7")


def fake_fetch(module, cve_dir):
    """실 git 대신 PoC 파일을 cve_dir 에 생성(조달 성공 흉내)."""
    p = os.path.join(cve_dir, "watchTowr-vs-FreePBX-CVE-2025-57819.py")
    with open(p, "w") as f:
        f.write("# poc\n")
    return True


print("=== fetch_module_poc: 주입 fetch_fn 으로 조달 → 경로 반환 ===")
with tempfile.TemporaryDirectory() as d:
    path = poc_fetch.fetch_module_poc(MOD, d, fetch_fn=fake_fetch)
    check("조달 경로 반환(.py 실제 파일)",
          bool(path) and path.endswith(".py") and os.path.isfile(path))

print("\n=== ASSASSIN_NO_NET → 실 네트워크 조달 차단 ===")
with tempfile.TemporaryDirectory() as d:
    os.environ["ASSASSIN_NO_NET"] = "1"
    path = poc_fetch.fetch_module_poc(MOD, d)   # fetch_fn 없음 + NO_NET
    check("NO_NET 이면 '' (받지 않음)", path == "")

print("\n=== 기존 조달분 재사용(재조달 안 함) ===")
with tempfile.TemporaryDirectory() as d:
    cve_dir = os.path.join(d, MOD.cve)
    os.makedirs(cve_dir)
    with open(os.path.join(cve_dir, "prev-CVE-2025-57819.py"), "w") as f:
        f.write("#")
    calls = {"n": 0}
    def counting(m, c):
        calls["n"] += 1
        return True
    path = poc_fetch.fetch_module_poc(MOD, d, fetch_fn=counting)
    check("기존 PoC 재사용 → fetch_fn 미호출", os.path.isfile(path) and calls["n"] == 0)


def make_orc(poc_dir, fetch):
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")), KnowledgeBase.load(),
                       auto_approve_contained, is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True, poc_dir=poc_dir, fetch_pocs=fetch)
    orc.world = WorldModel(target=T)
    orc.world.web_product = "freepbx"
    orc.world.web_version = "16.0.40.7"
    return orc


print("\n=== 오케스트레이터: fetch_pocs 옵트인 → 자동 조달 후 모듈 활성화·큐잉 ===")
with tempfile.TemporaryDirectory() as d:
    orc = make_orc(poc_dir=d, fetch=True)
    orc._poc_fetch_fn = fake_fetch
    rep = OrchestrationReport(target=T)
    orc._consider_builtin_exploit(rep, None)
    check("자동 조달 후 모듈 활성화", orc._active_exploit_module is not None
          and orc._active_exploit_module.cve == "CVE-2025-57819")
    check("조달된 PoC 로 실행 큐 투입", any(".py" in c for c in orc.poc_commands))
    check("자동 조달 안내 남김", any("자동 조달됨" in s for s in rep.manual_suggestions))

print("\n=== fetch_pocs OFF + 로컬 없음 → 조달 안 함(수동 안내만) ===")
with tempfile.TemporaryDirectory() as d:
    orc2 = make_orc(poc_dir=d, fetch=False)
    orc2._poc_fetch_fn = fake_fetch   # 주입돼 있어도 fetch_pocs OFF 면 호출 안 됨
    rep2 = OrchestrationReport(target=T)
    orc2._consider_builtin_exploit(rep2, None)
    check("OFF 면 모듈 활성화 안 함", orc2._active_exploit_module is None)
    check("OFF 면 큐 비어있음", not orc2.poc_commands)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
