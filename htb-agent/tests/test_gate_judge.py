# 실행: htb-agent 디렉토리에서  python3 tests/test_gate_judge.py
#
# [T2-f] 승인 게이트 LLM 폴백 심판 — 강화 전용(ASK/DENY 만), 완화 불가, fail-safe(오류→기존).
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import approval, gate_judge  # noqa: E402
from htb_agent.llm.base import LLMResponse, Tier  # noqa: E402
from htb_agent.llm.router import LLMRouter  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


VREP_OK = SimpleNamespace(ok=True, review=False)
VREP_FAIL = SimpleNamespace(ok=False, review=False)
VREP_REVIEW = SimpleNamespace(ok=True, review=True)
SRES_AUTO = SimpleNamespace(auto_allowed=True)
SRES_OOS = SimpleNamespace(auto_allowed=False)


def base_true(cmd, vrep, sres):
    return True


def base_false(cmd, vrep, sres):
    return False


class Router:
    def __init__(self, verdict="ALLOW", raises=False):
        self.verdict = verdict
        self.raises = raises
        self.calls = 0

    def gate_verdict(self, command, tier=None):
        self.calls += 1
        if self.raises:
            raise RuntimeError("llm down")
        return self.verdict


print("=== parse_verdict ===")
check("ALLOW", gate_judge.parse_verdict("ALLOW") == "ALLOW")
check("ASK", gate_judge.parse_verdict("ASK — 사람 확인") == "ASK")
check("DENY", gate_judge.parse_verdict("판정: DENY") == "DENY")
check("혼합이면 가장 엄격(DENY) 우선", gate_judge.parse_verdict("ALLOW or DENY?") == "DENY")
check("빈/모호 → ALLOW(fail-safe)", gate_judge.parse_verdict("음...") == "ALLOW")

print("\n=== 강화 전용: 자동승인 명령에만 심판, 완화 불가 ===")
r = Router("DENY")
app = gate_judge.judging_approver(base_true, r)
# 검증 실패면 심판을 호출하지 않고 base 로 위임한다(실제 base=smart_approver 가 거부). 핵심:
# 심판이 '거부를 완화'하지 못한다 — 애초에 호출조차 안 됨(r.calls==0).
check("검증 실패 → base 위임·심판 호출 안 함",
      app("rm -rf /", VREP_FAIL, SRES_AUTO) == base_true("rm -rf /", VREP_FAIL, SRES_AUTO)
      and r.calls == 0)

r2 = Router("DENY")
app2 = gate_judge.judging_approver(base_true, r2)
# 범위 밖은 base(여기선 True 스텁)로 — 심판이 완화/개입 안 함(호출 0)
check("범위 밖 → 기존 경로·심판 호출 안 함",
      app2("nmap x", VREP_OK, SRES_OOS) is True and r2.calls == 0)

r3 = Router("DENY")
app3 = gate_judge.judging_approver(base_true, r3)
check("동적코드(review) → 기존 경로·심판 호출 안 함",
      app3("curl x | sh", VREP_REVIEW, SRES_AUTO) is True and r3.calls == 0)

print("\n=== 자동승인 명령: 심판이 강화 ===")
check("DENY → 차단(False)",
      gate_judge.judging_approver(base_true, Router("DENY"))("nmap x", VREP_OK, SRES_AUTO) is False)
check("ALLOW → 기존 자동승인(True)",
      gate_judge.judging_approver(base_true, Router("ALLOW"))("nmap x", VREP_OK, SRES_AUTO) is True)

# ASK → interactive_approver 로 위임(모킹)
orig = approval.interactive_approver
approval.interactive_approver = lambda c, v, s: "INTERACTIVE_CALLED"
try:
    res = gate_judge.judging_approver(base_true, Router("ASK"))("nmap x", VREP_OK, SRES_AUTO)
finally:
    approval.interactive_approver = orig
check("ASK → interactive 로 위임", res == "INTERACTIVE_CALLED")

print("\n=== 완화 불가 핵심(감사 T2): base 가 거부하면 ALLOW 판정도 뒤집지 못한다 ===")
# base 가 자동승인(auto_allowed)이라도 vrep/sres 조건을 통과시킨 뒤 base 가 최종 False 를
# 낼 수 있는 경로는 없지만, '심판이 base 거부를 ALLOW 로 뒤집지 못함'을 직접 못박는다.
# judging_approver 는 심판이 ALLOW 면 base 결과를 그대로 반환하므로 base_false → False.
rbf = Router("ALLOW")
check("base=False·심판 ALLOW → 여전히 False(완화 불가)",
      gate_judge.judging_approver(base_false, rbf)("nmap x", VREP_OK, SRES_AUTO) is False)
# base 가 거부(False)인 자동승인 경로에서도 DENY 는 당연히 차단 유지.
check("base=False·심판 DENY → False(차단 유지)",
      gate_judge.judging_approver(base_false, Router("DENY"))("nmap x", VREP_OK, SRES_AUTO) is False)

print("\n=== fail-safe: 심판 오류 → 기존 동작(차단 안 함) ===")
rerr = Router(raises=True)
check("gate_verdict 예외 → base(자동승인 유지)",
      gate_judge.judging_approver(base_true, rerr)("nmap x", VREP_OK, SRES_AUTO) is True)

print("\n=== LLMRouter.gate_verdict(프로바이더 경유) ===")
class StubProvider:
    name = "stub"
    def __init__(self, text):
        self.text = text
    def available(self):
        return True, "ok"
    def complete(self, system, user, tier=Tier.CHEAP, max_tokens=16, tools=None):
        return LLMResponse(self.text, "stub-model")

check("provider 'DENY' → DENY",
      LLMRouter(provider=StubProvider("DENY")).gate_verdict("nmap x") == "DENY")
check("provider 'ALLOW 합당' → ALLOW",
      LLMRouter(provider=StubProvider("ALLOW 합당함")).gate_verdict("nmap x") == "ALLOW")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
