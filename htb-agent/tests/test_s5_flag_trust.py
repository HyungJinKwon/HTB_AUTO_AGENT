# 실행: htb-agent 디렉토리에서  python3 tests/test_s5_flag_trust.py
#
# S5-2 — 정직성 가드: world(신뢰 상태·권한레벨)에는 공략 유래(exploit-derived) 플래그만
# 반영한다. 로컬 출력의 미끼/라이트업 유래 플래그가 world.access_level 을 올려 _prereq_met 를
# 충족시키던(투기적 LLM 라운드 오발) 결함 교정을 고정한다. report.flags 는 전부 기록(사람 확인용).
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

def prov(kind, val, verdict):
    return _prov.FlagProvenance(kind, val, "cmd", "enum", verdict, "r")

print("=== 미신뢰 플래그: report 엔 들어가되 world 권한레벨은 오염 안 됨 ===")
o = mk(); rep = OrchestrationReport(target=T, flag_kind="boot2root")
# 로컬 유래(지어낸 값일 수 있음) root 플래그 — goal 도 world 도 신뢰하면 안 됨
o._record_flag(rep, FlagHit("HTB{decoy}", "root", "cat"), prov("root", "HTB{decoy}", "local-derived"))
check("report.flags 엔 기록(사람 확인용)", any(f.value == "HTB{decoy}" for f in rep.flags))
check("world.flags 엔 미반영", "root" not in o.world.flags)
check("world.access_level 오염 안 됨(none 유지)", o.world.access_level == "none")
check("goal_reached False(신뢰 플래그 아님)", o._goal_reached(rep) is False)

print("\n=== looked-up(라이트업 유래)도 world 미반영 ===")
o2 = mk(); rep2 = OrchestrationReport(target=T, flag_kind="boot2root")
o2._record_flag(rep2, FlagHit("HTB{seen}", "user", "curl"), prov("user", "HTB{seen}", "looked-up"))
check("looked-up → world 미반영·권한 none", "user" not in o2.world.flags and o2.world.access_level == "none")
check("report 엔 존재", rep2.user_flag == "HTB{seen}")

print("\n=== 공략 유래(exploit-derived)는 정상 반영·권한 승격 ===")
o3 = mk(); rep3 = OrchestrationReport(target=T, flag_kind="boot2root")
o3._record_flag(rep3, FlagHit("HTB{real}", "user", "curl"), prov("user", "HTB{real}", "exploit-derived"))
check("exploit-derived → world.flags 반영", o3.world.flags.get("user") == "HTB{real}")
check("world 권한레벨 user 승격", o3.world.has_access("user"))

print("\n=== 혼합: 미신뢰 root + 신뢰 user → 권한은 user 까지만(미신뢰 root 로 안 올라감) ===")
o4 = mk(); rep4 = OrchestrationReport(target=T, flag_kind="boot2root")
o4._record_flag(rep4, FlagHit("HTB{u}", "user", "curl"), prov("user", "HTB{u}", "exploit-derived"))
o4._record_flag(rep4, FlagHit("HTB{fake_root}", "root", "cat"), prov("root", "HTB{fake_root}", "local-derived"))
check("world 권한레벨 user(미신뢰 root 로 root 승격 안 됨)", o4.world.access_level == "user")
check("goal_reached False(root 는 신뢰 플래그 없음)", o4._goal_reached(rep4) is False)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
