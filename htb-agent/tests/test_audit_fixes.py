# 실행: htb-agent 디렉토리에서  python3 tests/test_audit_fixes.py
#
# 적대적 감사 후속 수정 회귀:
#   [M1] _record_signal 의 '막힘' 경고/audit 임계가 고정 replan_after 가 아니라 가설별
#        budget(h) 를 쓴다(focus()/stuck() 와 일관).
#   [M2] _analyze_offline_files 가 재개 복원분(이미 투입된 명령)을 재실행하지 않는다.
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import reversing  # noqa: E402
from htb_agent.hypotheses import Hypothesis, HypothesisLedger  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import EnumFinding, OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


class AuditStub:
    def __init__(self):
        self.events = []

    def event(self, name, **kw):
        self.events.append((name, kw))


def new_orc():
    g = ScopeGuard.from_cidr_strings()
    g.bind_target("10.129.1.5")
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="ok")),
                       KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                       is_tool_available=lambda b: True, quiet=True)
    orc.audit = AuditStub()
    orc.world = WorldModel(target="10.129.1.5")
    return orc


print("=== [M1] 막힘 임계 = 가설별 budget(h)(고정 replan_after 아님) ===")
# budget 계산 전제 확인: 고영향('상')·저비용('하') → budget=round(2*3/1)=6 ≠ replan_after(2).
led = HypothesisLedger(items=[Hypothesis(id="H1", text="t", expected="NEVERMATCH",
                                         impact="상", cost="하", status="pending")])
check("전제: H1 budget==6, replan_after==2(다름)",
      led.budget(led.get("H1")) == 6 and led.replan_after == 2)

orc = new_orc()
rep = OrchestrationReport(target="10.129.1.5")
rep.plan = led
rep.world = orc.world
f = EnumFinding(command="probe-cmd", phase="enum")
f.ran = True
f.output = ""   # 빈 출력 → record() 에서 miss(연속 불일치 +1)

meta = {"hypothesis": "H1"}
fires = []
for i in range(1, 7):
    orc.audit.events.clear()
    orc._record_signal(rep, f, meta, None)
    stuck = [e for e in orc.audit.events if e[0] == "hypothesis_stuck"]
    if stuck:
        fires.append((i, led.get("H1").misses))
check("replan_after(2)회에서는 '막힘' 경고 미발화(고정 임계 아님)",
      all(misses != 2 for _, misses in fires) and led.get("H1").misses == 6)
check("budget(6)회에서 정확히 1회 발화", len(fires) == 1 and fires[0][1] == 6)

# 저영향·고비용 가설(budget=1)은 첫 불일치에서 발화 — stuck() 과 일관.
led2 = HypothesisLedger(items=[Hypothesis(id="H2", text="t", expected="NEVERMATCH",
                                          impact="하", cost="상", status="pending")])
check("전제: H2 budget==1", led2.budget(led2.get("H2")) == 1)
orc2 = new_orc()
rep2 = OrchestrationReport(target="10.129.1.5")
rep2.plan = led2
rep2.world = orc2.world
orc2._record_signal(rep2, EnumFinding(command="c", phase="enum", ran=True, output=""),
                    {"hypothesis": "H2"}, None)
check("저예산(1) 가설은 첫 불일치에서 '막힘' 발화",
      any(e[0] == "hypothesis_stuck" for e in orc2.audit.events))


print("\n=== [M2] _analyze_offline_files: 재개 복원분 재실행 안 함 ===")
orc3 = new_orc()
rep3 = OrchestrationReport(target="10.129.1.5")
rep3.world = orc3.world
rel = "crackme"
root = "/tmp/assassin-test-ws"
cmds = reversing.export_first_commands(os.path.join(root, rel))
check("전제: export-first 명령 다수 생성", len(cmds) >= 3)
# 재개 상황 모사: 첫 명령이 이미 이전 run 에서 투입됨(복원분).
rep3.enum_findings.append(EnumFinding(command=cmds[0], phase="access", ran=True))
orc3.workspace = SimpleNamespace(imported=[rel], root=root,
                                 resolve=lambda r: os.path.join(root, r))
orc3._analyze_offline_files(rep3)
n_dup = sum(1 for f in rep3.enum_findings if f.command == cmds[0])
check("복원된 cmds[0] 는 재투입 안 됨(중복 1개뿐)", n_dup == 1)
check("나머지 명령들은 정상 투입됨",
      all(any(f.command == c for f in rep3.enum_findings) for c in cmds[1:]))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
