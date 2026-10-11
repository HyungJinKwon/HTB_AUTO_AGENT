# 실행: htb-agent 디렉토리에서  python3 tests/test_s4_flag_ssot.py
#
# S4-2 — 플래그 상태원 단일 쓰기 경로(_record_flag): report.flags + flag_provenance +
# world.flags 가 한 경로로 함께 갱신되는지, 그리고 '발판 경로 world-only 기록 → report
# 누락 → goal_reached 못 봄' 결함이 교정됐는지 고정한다.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard               # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput   # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope    # noqa: E402
from htb_agent.knowledge import KnowledgeBase              # noqa: E402
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
def mk():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    o = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="")),
                     KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True)
    o.world = WorldModel(target=T)
    return o

print("=== _record_flag: report.flags + flag_provenance + world.flags 동시 갱신 ===")
o = mk()
rep = OrchestrationReport(target=T, flag_kind="boot2root")
prov = _prov.FlagProvenance("user", "HTB{u}", "cmd", "enum", "exploit-derived", "r")
new = o._record_flag(rep, FlagHit("HTB{u}", "user", "src"), prov)
check("신규 기록 True", new is True)
check("report.flags 반영", any(f.value == "HTB{u}" for f in rep.flags))
check("flag_provenance 반영", any(p.value == "HTB{u}" for p in rep.flag_provenance))
check("world.flags 반영", o.world.flags.get("user") == "HTB{u}")
check("world 권한레벨 user 승격", o.world.has_access("user"))

print("\n=== 중복은 무시(값 기준) ===")
dup = o._record_flag(rep, FlagHit("HTB{u}", "user", "src2"), prov)
check("중복 기록 False", dup is False)
check("report.flags 1건 유지", sum(1 for f in rep.flags if f.value == "HTB{u}") == 1)

print("\n=== prov 없이도 기록(상태만) ===")
o2 = mk(); rep2 = OrchestrationReport(target=T, flag_kind="boot2root")
o2._record_flag(rep2, FlagHit("HTB{x}", "root", "s"))
check("prov 없음 — report.flags 반영", any(f.value == "HTB{x}" for f in rep2.flags))
check("prov 없음 — flag_provenance 비어 있음", rep2.flag_provenance == [])

print("\n=== goal_reached: exploit-derived provenance 로 기록된 user+root 인정 ===")
o3 = mk(); rep3 = OrchestrationReport(target=T, flag_kind="boot2root")
for k in ("user", "root"):
    p = _prov.FlagProvenance(k, f"HTB{{{k}}}", "<발판 세션 직독>", "foothold",
                             "exploit-derived", "발판 세션에서 직접 읽음")
    o3._record_flag(rep3, FlagHit(f"HTB{{{k}}}", k, "발판"), p)
check("발판 유래 user+root → goal_reached True", o3._goal_reached(rep3) is True)
check("report.user_flag 노출", rep3.user_flag == "HTB{user}")
check("report.root_flag 노출", rep3.root_flag == "HTB{root}")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
