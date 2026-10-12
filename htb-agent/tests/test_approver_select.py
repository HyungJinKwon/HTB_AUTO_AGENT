# 실행: htb-agent 디렉토리에서  python3 tests/test_approver_select.py
#
# [감사 H1] 승인자 선택 단일화 — main.select_approver 가 실행기(contained)·gate-judge 를
# '한 곳에서' 조립한다. 과거엔 gate-judge 래핑 뒤에 contained 자동승인이 재대입돼 자율+샌드박스
# 에서 gate-judge 가 조용히 죽었다. 이 테스트가 그 순서 역전을 못박는다.
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import main as M  # noqa: E402
from htb_agent.approval import interactive_approver, smart_approver  # noqa: E402
from htb_agent.tools.recon import auto_approve_contained, auto_approve_in_scope  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


class DenyRouter:
    def gate_verdict(self, command, tier=None):
        return "DENY"


def sel(**kw):
    base = dict(manual=False, auto=False, autonomous=False,
                contained=False, gate_judge=False, llm_router=None)
    base.update(kw)
    return M.select_approver(**base)


print("=== 기본 선택(우선순위) ===")
check("--manual 이 autonomous 보다 우선 → interactive",
      sel(manual=True, auto=True, autonomous=True, contained=True) is interactive_approver)
check("auto + contained → auto_approve_contained",
      sel(auto=True, contained=True) is auto_approve_contained)
check("auto + 비contained → auto_approve_in_scope",
      sel(auto=True, contained=False) is auto_approve_in_scope)
check("autonomous + contained → auto_approve_contained",
      sel(autonomous=True, contained=True) is auto_approve_contained)
check("기본(비자동) → smart_approver", sel() is smart_approver)

print("\n=== H1 회귀: gate-judge 가 contained 자동승인에 덮이지 않는다 ===")
a = sel(auto=True, contained=True, gate_judge=True, llm_router=DenyRouter())
check("auto+contained+gate_judge → bare auto_approve_contained 아님(래핑 생존)",
      a is not auto_approve_contained and callable(a))
# 행동 검증: 자동승인될 명령(검증 OK·자동허용)을 심판 DENY 가 실제로 차단한다.
VREP_OK = SimpleNamespace(ok=True, review=False)
SRES_AUTO = SimpleNamespace(auto_allowed=True)
check("auto+contained+gate_judge: 심판 DENY 가 자동승인을 실제 차단(False)",
      a("nmap 10.129.1.5", VREP_OK, SRES_AUTO) is False)

print("\n=== gate_judge opt-in 조건 ===")
check("gate_judge=True·router None → 래핑 안 함(base 유지)",
      sel(auto=True, contained=True, gate_judge=True, llm_router=None) is auto_approve_contained)
check("gate_judge=False → 래핑 안 함(base 유지)",
      sel(auto=True, contained=True, gate_judge=False, llm_router=DenyRouter()) is auto_approve_contained)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
