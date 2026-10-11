# 실행: htb-agent 디렉토리에서  python3 tests/test_judge.py
#
# A6 — LLM-심판 게이트(opt-in·advisory): 증거가 '공략 달성'을 뒷받침하는지 별도 LLM 채점.
# 규칙 판정(goal_reached·provenance)을 '절대 덮지 않음'을 고정한다.
import sys
sys.path.insert(0, "src")
from htb_agent import judge as J                            # noqa: E402
from htb_agent.scope_guard import ScopeGuard                # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput    # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope     # noqa: E402
from htb_agent.knowledge import KnowledgeBase               # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider        # noqa: E402
from htb_agent.llm.router import LLMRouter                   # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                      # noqa: E402
from htb_agent.flag import FlagHit                          # noqa: E402
from htb_agent import provenance as _prov                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== parse_judge: JSON 파싱·클램프·폴백 ===")
v = J.parse_judge('{"score": 85, "passed": true, "rationale": "원격 RCE 로 획득"}')
check("점수/통과/사유 파싱", v and v.score == 85 and v.passed and "RCE" in v.rationale)
v2 = J.parse_judge('앞 설명... {"score": 150, "passed": false} 뒤 설명')
check("범위 클램프(>100→100)·JSON 추출", v2 and v2.score == 100 and v2.passed is False)
check("빈/비JSON → None", J.parse_judge("") is None and J.parse_judge("설명만") is None)
v3 = J.parse_judge('{"score": 40}')
check("passed 미지정 → score>=70 규칙", v3 and v3.passed is False)

print("\n=== build_judge_user: 증거 요약 포함 ===")
u = J.build_judge_user({"flags": ["root=HTB{x} (출처판정: exploit-derived)"],
                        "access_level": "root", "state": ["권한레벨=root"],
                        "commands": ["curl http://t/"]}, "10.129.1.5")
check("플래그·타겟 포함", "HTB{x}" in u and "10.129.1.5" in u)

print("\n=== 라우터 judge() 경로(FakeProvider) ===")
def fake_judge(system, user, tier):
    if "심판" in system:   # 심판 프롬프트
        return '{"score": 90, "passed": true, "rationale": "발판 세션에서 직접 확인"}'
    return "분석..."
r = LLMRouter(FakeProvider(fake_judge))
raw = r.judge({"flags": ["user=HTB{u}"]}, "10.129.1.5")
check("라우터 judge() → 심판 JSON", J.parse_judge(raw).score == 90)

print("\n=== 오케스트레이터: --judge 켜야만·규칙 판정 불변 ===")
T = "10.129.1.5"
XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http"/></port></ports></host></nmaprun>"""
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                      else RunOutput(c, stdout="ok"))
def mk(judge_on):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    return Orchestrator(g, runner(), KnowledgeBase.load(), auto_approve_in_scope,
                        llm_router=LLMRouter(FakeProvider(fake_judge)),
                        judge=judge_on, is_tool_available=lambda b: True, quiet=True,
                        max_sweeps=1, max_rounds=1)

rep_off = mk(False).run()
check("--judge OFF → judge_verdict 없음(기본 비용 0)", rep_off.judge_verdict is None)
rep_on = mk(True).run()
check("--judge ON → judge_verdict 조언 기록", rep_on.judge_verdict is not None
      and rep_on.judge_verdict.score == 90)
check("심판이 pass 해도 goal_reached 는 규칙대로(플래그 없음→False)",
      rep_on.goal_reached is False)

print("\n=== 정직성: 심판은 미신뢰 플래그를 승격하지 않음(조언만) ===")
o = mk(True); o.world = WorldModel(target=T)
rep = OrchestrationReport(target=T, flag_kind="boot2root")
# 미신뢰(local-derived) root 플래그만 — world 권한 none 유지(S5-2), 심판은 조언만
o._record_flag(rep, FlagHit("HTB{decoy}", "root", "cat"),
               _prov.FlagProvenance("root", "HTB{decoy}", "cat", "enum", "local-derived", "r"))
o._run_judge(rep, T)
check("심판 조언 존재", rep.judge_verdict is not None)
check("미신뢰 플래그로 goal_reached False 유지", o._goal_reached(rep) is False)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
