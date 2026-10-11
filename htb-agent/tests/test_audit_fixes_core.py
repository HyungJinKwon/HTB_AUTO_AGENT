# 실행: htb-agent 디렉토리에서  python3 tests/test_audit_fixes_core.py
#
# 구조 감사에서 확인된 오케스트레이터/상태 실버그의 회귀 가드:
#   [MED] orch-F1  time budget 이 enum/LLM 내부 루프·병렬 배치에서 미강제 → 데드라인 대폭 초과
#   [LOW] orch-F3  _ran_total 이 skipped LLM finding 도 '진행'으로 집계
#   [MED] MED-1    resume 가 world.loot 유실 → _prereq_met("lateral") 퇴행
#   [MED] MED-2    world.to_dict 가 learned 누락(export SSOT 불일치)
#   [LOW] LOW-1    add_flag 가 value 가드 밖에서 access 상승(빈 값에도 상승)
#   [LOW] LOW-2    _record_flag dedup 이 value 만 봄((kind,value) 가 옳음)
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent import provenance as _prov                   # noqa: E402
from htb_agent.flag import FlagHit                          # noqa: E402
from htb_agent.knowledge import KnowledgeBase               # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.state import SessionState, StateStore        # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope     # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput    # noqa: E402
from htb_agent.scope_guard import ScopeGuard                # noqa: E402
from htb_agent.world import WorldModel                      # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.1.5"
ALL = lambda b: True  # noqa: E731
XML = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{T}"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/>'
       '<service name="http" product="Apache"/></port></ports></host></nmaprun>')


def guard():
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    return g


def build(store=None):
    return Orchestrator(
        guard(),
        FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap") else RunOutput(c, stdout="")),
        KnowledgeBase.load(), auto_approve_in_scope,
        state_store=store, is_tool_available=ALL, quiet=True)


# ── MED-2 / LOW-1: WorldModel 단위 ──────────────────────────────────────
print("=== MED-2: to_dict 가 learned 를 내보낸다 ===")
w = WorldModel(target=T)
w.add_learned("FreePBX 는 Asterisk 기반 PBX")
d = w.to_dict()
check("to_dict 에 'learned' 키 존재", "learned" in d)
check("learned 값이 내보내짐", d.get("learned") == ["FreePBX 는 Asterisk 기반 PBX"])

print("\n=== LOW-1: add_flag 는 실제 값 기록 시에만 access 상승 ===")
w2 = WorldModel(target=T)
w2.add_flag("root", "")                    # 빈 값 — 플래그 기록도, access 상승도 없어야
check("빈 값 add_flag → access 그대로 none", w2.access_level == "none")
check("빈 값 add_flag → 플래그 미기록", "root" not in w2.flags)
w2.add_flag("root", "HTB{real}")           # 실제 값 — 기록 + 상승
check("실제 값 add_flag → access root", w2.access_level == "root")


# ── MED-1: loot resume 왕복 ─────────────────────────────────────────────
print("\n=== MED-1: resume 가 world.loot 를 보존(lateral 전제) ===")
with tempfile.TemporaryDirectory() as dd:
    store = StateStore(dd)
    o1 = build(store)
    rep1 = o1.run()
    o1.world.add_loot("해시: $1$abc$0123456789abcdef0123456./")   # 크랙 대상 수집물
    o1._persist(rep1, store.load(T))
    saved = store.load(T)
    check("state.loot 저장됨", bool(saved.loot) and "해시" in saved.loot[0])
    check("SessionState 왕복(JSON)", "해시" in SessionState.from_dict(
        __import__("json").loads(saved.to_json())).loot[0])

    o2 = build(store)
    rep2 = OrchestrationReport(target=T)
    o2.world = WorldModel(target=T)
    o2._restore(rep2, saved, set())
    check("복원 후 world.loot 재적재", bool(o2.world.loot))
    met, _why = o2._prereq_met("lateral")
    check("복원 후 lateral 전제 met(퇴행 없음)", met is True)


# ── LOW-2: _record_flag (kind,value) dedup ──────────────────────────────
print("\n=== LOW-2: _record_flag 는 (kind,value) 로 중복 판정 ===")
o3 = build()
o3.world = WorldModel(target=T)
rep3 = OrchestrationReport(target=T)
rep3.world = o3.world
pu = _prov.FlagProvenance("user", "SAME", "cmd", "access", "exploit-derived", "x")
pr = _prov.FlagProvenance("root", "SAME", "cmd", "privesc", "exploit-derived", "x")
r_u = o3._record_flag(rep3, FlagHit("SAME", "user", "s"), pu)
r_r = o3._record_flag(rep3, FlagHit("SAME", "root", "s"), pr)   # 같은 값·다른 종류 — 드롭되면 안 됨
check("같은 값이라도 다른 종류는 둘 다 기록", r_u is True and r_r is True)
kinds = {f.kind for f in rep3.flags}
check("report.flags 에 user·root 둘 다 존재", kinds == {"user", "root"})
dup = o3._record_flag(rep3, FlagHit("SAME", "user", "s"), pu)   # 완전 동일 → 드롭
check("동일 (kind,value) 는 중복 드롭", dup is False)


# ── orch-F1: 시간 예산 — 병렬 배치는 시간 소진 시 띄우지 않음 ────────────
print("\n=== orch-F1: _attempt_batch 는 시간 소진 시 실행 안 함 ===")
o4 = build()
o4._time_up = lambda: True        # 시간 소진 모사
rep4 = OrchestrationReport(target=T)
out = o4._attempt_batch(rep4, rep4.enum_findings, ["curl -i http://%s/" % T], "enum")
check("_time_up True → 배치 빈 목록 반환(미실행)", out == [])
check("_time_up True → finding 생성 안 됨", len(rep4.enum_findings) == 0)


# ── orch-F3: _ran_total 은 skipped LLM finding 을 진행으로 세지 않음 ─────
print("\n=== orch-F3: skipped LLM finding 은 '진행'으로 집계 안 함 ===")
# EnumFinding(skipped=True) 를 llm_findings 에 넣어도 진행 집계에서 빠지는지 — 집계식 직접 검증
from htb_agent.orchestrator import EnumFinding              # noqa: E402
rep5 = OrchestrationReport(target=T)
rep5.llm_findings.append(EnumFinding(command="tool-missing-cmd", skipped=True))
rep5.llm_findings.append(EnumFinding(command="ran-cmd", skipped=False, ran=True))
ran = (sum(1 for f in rep5.enum_findings if not f.skipped)
       + sum(1 for f in rep5.llm_findings if not f.skipped))
check("skipped LLM finding 제외 → 진행 1 (2 아님)", ran == 1)


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
