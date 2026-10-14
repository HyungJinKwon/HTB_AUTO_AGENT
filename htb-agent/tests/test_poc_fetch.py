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

print("\n=== PoC 의존성 자가치유: 빠진 모듈명 파싱 ===")
check("ModuleNotFoundError → 모듈명",
      poc_fetch.missing_module("Traceback ... ModuleNotFoundError: No module named 'urllib3'") == "urllib3")
check("점분리는 최상위로 축약",
      poc_fetch.missing_module("No module named 'requests.adapters'") == "requests")
check("표준 라이브러리는 설치 대상 아님(빈 문자열)",
      poc_fetch.missing_module("No module named 'os'") == "")
check("정상 출력엔 없음", poc_fetch.missing_module("webshell: http://t/s.php?cmd=") == "")

print("\n=== ensure_module: 이미 있으면 설치 안 함 / 없으면 주입 pip 호출 ===")
check("이미 있는 모듈(os) → 설치 미호출·True",
      poc_fetch.ensure_module("os", pip_fn=lambda n: (_ for _ in ()).throw(AssertionError("설치 금지"))))
installed = []
check("없는 모듈 → pip_fn 호출·성공 True",
      poc_fetch.ensure_module("totally_missing_pkg_xyz", pip_fn=lambda n: installed.append(n) or True))
check("설치된 이름 전달됨", installed == ["totally_missing_pkg_xyz"])
check("잘못된 모듈명(인자 주입 차단)",
      not poc_fetch.ensure_module("evil; rm -rf /", pip_fn=lambda n: True))
os.environ["ASSASSIN_NO_NET"] = "1"
check("ASSASSIN_NO_NET → 설치 안 함(False)",
      not poc_fetch.ensure_module("another_missing_pkg_xyz"))
os.environ.pop("ASSASSIN_NO_NET", None)

print("\n=== _run_one_poc: PoC 가 의존성 부족으로 죽으면 자동 설치 후 1회 재실행 ===")
# PoC 출력이 처음엔 'No module named urllib3', 설치 후 재실행하면 웹셸 URL 을 뱉도록 러너를 구성.
state = {"ran": 0}
def poc_runner(cmd):
    if "python3 /poc.py" in cmd:
        state["ran"] += 1
        if state["ran"] == 1:
            return RunOutput(cmd, "Traceback\nModuleNotFoundError: No module named 'urllib3'")
        return RunOutput(cmd, "[+] webshell dropped: http://10.129.245.100/shell.php?cmd=")
    return RunOutput(cmd, "")
g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
orcH = Orchestrator(g, FakeRunner(poc_runner), KnowledgeBase.load(), auto_approve_contained,
                    is_tool_available=lambda b: True, quiet=True,
                    exploit_exec=True, auto_poc=True, fetch_pocs=True)
orcH.world = WorldModel(target=T)
orcH.poc_commands = ["python3 /poc.py -H https://10.129.245.100/"]
# 실제 pip 대신 '설치 성공' 주입(네트워크 없음)
import htb_agent.poc_fetch as _pf
_orig_pip = _pf._pip_install
_pf._pip_install = lambda modname, timeout=180.0: True
try:
    repH = OrchestrationReport(target=T)
    orcH._exploit_run_stage(repH, None)
finally:
    _pf._pip_install = _orig_pip
check("의존성 부족 PoC → 재실행됨(2회)", state["ran"] == 2)
check("재실행 후 웹셸 URL 캡처(rce_url)", getattr(orcH, "rce_url", "").endswith("shell.php?cmd="))
check("자동 설치 안내 남김", any("의존성 자동 설치" in s for s in repH.manual_suggestions))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
