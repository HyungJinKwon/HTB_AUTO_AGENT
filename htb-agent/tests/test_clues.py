# 실행: htb-agent 디렉토리에서  python3 tests/test_clues.py
#
# clues.py (해커톤 lab 에서 이식) — 교차단계 '단서'(host/user/path/hash/software) 누적 +
# LLM 후보생성 컨텍스트 되먹임(Contextual Amnesia 완화). 순수 추출 + 라우터 프롬프트 렌더 배선.
import sys

sys.path.insert(0, "src")

from htb_agent.clues import ClueStore                       # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider        # noqa: E402
from htb_agent.llm.router import LLMRouter                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== ClueStore — add 중복제거·상한 ===")
cs = ClueStore(per_kind_cap=3)
check("add 성공", cs.add("user", "kevin"))
check("중복 add 거부", not cs.add("user", "kevin"))
check("빈 값 거부", not cs.add("user", "  "))
cs.add("user", "bob"); cs.add("user", "carol")
check("상한 초과 거부", not cs.add("user", "dave"))
check("__bool__ True", bool(cs))
check("빈 스토어 __bool__ False", not bool(ClueStore()))

print("\n=== harvest — 종류별 추출 ===")
cs = ClueStore()
n = cs.harvest("Nmap scan report for dc01.corp.htb\nusername: kevin\n"
               "found /var/backups/config.bak and OpenSSH 8.2\n"
               "hash 5f4dcc3b5aa765d61d8327deb882cf99")
k = cs.kinds()
check("host 단서(dc01.corp.htb)", "dc01.corp.htb" in k.get("host", []))
check("user 단서(kevin)", "kevin" in k.get("user", []))
check("path 단서(config.bak)", any("config.bak" in p for p in k.get("path", [])))
check("software 단서(OpenSSH 8.2)", any("OpenSSH 8.2" in s for s in k.get("software", [])))
check("hash 단서(32hex)", "5f4dcc3b5aa765d61d8327deb882cf99" in k.get("hash", []))
check("harvest 반환 = 추가 수", n == sum(len(v) for v in k.values()))

print("\n=== hash 는 플래그 파일 맥락이면 제외(플래그는 flag.py 담당) ===")
cs2 = ClueStore()
cs2.harvest("cat user.txt => 5f4dcc3b5aa765d61d8327deb882cf99")
check("user.txt 맥락의 32hex 는 단서 아님", "hash" not in cs2.kinds())

print("\n=== context_lines — 종류별 상위 N ===")
cs3 = ClueStore()
for i in range(10):
    cs3.add("user", f"u{i}")
lines = cs3.context_lines(per_kind=4)
check("종류별 상위 4개만", lines and lines[0].startswith("user: ") and lines[0].count(",") == 3)

print("\n=== 라우터 프롬프트 배선 — clues 가 suggest 사용자 프롬프트에 렌더 ===")
cap: list[str] = []
def _spy(system, user, tier):
    cap.append(user)   # suggest_commands 가 넘기는 user 프롬프트 포착
    return ""          # 명령 없음(파싱 무관 — 프롬프트 내용만 검증)
r = LLMRouter(FakeProvider(_spy))
r.suggest_commands({"clues": ["host: enigma.htb", "user: kevin"],
                    "findings": ["nmap => 22,80 open"]}, "10.129.1.5")
check("환경 단서 섹션이 suggest 프롬프트에 렌더됨", cap and "환경 단서" in cap[0])
check("단서 값 포함(enigma.htb)", cap and "enigma.htb" in cap[0])
cap.clear()
r.suggest_commands({"findings": ["x"]}, "10.129.1.5")
check("clues 없으면 섹션 없음", cap and "환경 단서" not in cap[0])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
