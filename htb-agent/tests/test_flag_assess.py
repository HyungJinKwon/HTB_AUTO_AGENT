# 실행: htb-agent 디렉토리에서  python3 tests/test_flag_assess.py
#
# S4-3(2) — god-object 해체로 분리한 flag_assess 자유 함수의 단위 검증(분류·확신도).
import sys
sys.path.insert(0, "src")
from htb_agent import flag_assess as FA                      # noqa: E402
from htb_agent.orchestrator import OrchestrationReport       # noqa: E402
from htb_agent.flag import FlagHit                           # noqa: E402
from htb_agent.observation.parsers import NmapHost           # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"

class _KB:   # external_notes() 만 제공하는 덕타이핑 KB
    def __init__(self, notes): self._n = notes
    def external_notes(self): return self._n

print("=== flag_in_external_notes ===")
check("외부 노트에 있으면 True", FA.flag_in_external_notes("HTB{x}", _KB(["... HTB{x} ..."])) is True)
check("없으면 False", FA.flag_in_external_notes("HTB{x}", _KB(["무관"])) is False)
check("kb None 이면 False", FA.flag_in_external_notes("HTB{x}", None) is False)
check("빈 값 False", FA.flag_in_external_notes("", _KB(["HTB{x}"])) is False)

print("\n=== classify_flag: 외부노트 유래 → looked-up ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root")
prov = FA.classify_flag(rep, FlagHit("HTB{seen}", "user", "s"),
                        "curl http://t/", "enum", None, _KB(["HTB{seen} 라이트업"]))
check("외부 노트에 있던 값 → looked-up", prov.verdict == "looked-up")

print("\n=== classify_flag: 대상 상호작용 → exploit-derived ===")
rep2 = OrchestrationReport(target=T, flag_kind="boot2root")
prov2 = FA.classify_flag(rep2, FlagHit("HTB{pwn}", "root", "s"),
                         "curl -s http://10.129.1.5/flag", "enum", None, _KB([]))
check("원격 상호작용 유래 → exploit-derived", prov2.verdict == "exploit-derived")

print("\n=== assess_flags: flag_confidence 채움 ===")
from htb_agent import provenance as _prov                    # noqa: E402
rep3 = OrchestrationReport(target=T, flag_kind="boot2root")
rep3.host = NmapHost(address=T, state="up")
rep3.flags.append(FlagHit("HTB{u}", "user", "curl http://t/"))
rep3.flag_provenance.append(
    _prov.FlagProvenance("user", "HTB{u}", "curl http://t/", "enum", "exploit-derived", "r"))
FA.assess_flags(rep3)
check("flag_confidence 에 평가 결과 기록", ("user", "HTB{u}") in rep3.flag_confidence)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
