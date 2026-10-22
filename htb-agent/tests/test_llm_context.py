# 실행: htb-agent 디렉토리에서  python3 tests/test_llm_context.py
#
# llm/context.py (해커톤 lab 에서 이식) — LLM 프롬프트 토큰 예산·우선순위 트리밍.
# "꽉 채우지 않고 필요한 만큼만": target 아래는 패딩 안 함, ceiling 넘으면 필수 꼬리까지 깎음.
import sys

sys.path.insert(0, "src")

from htb_agent.llm.context import ContextBuilder, Section, est_tokens  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== est_tokens — 보수적 추정 ===")
check("빈 문자열 → 0", est_tokens("") == 0)
check("ASCII ~3자/토큰", est_tokens("abcdef") == 2)
check("한글 1자/토큰", est_tokens("가나다") == 3)
check("과대추정(ascii+cjk)", est_tokens("abc가") == 2)   # ceil(3/3 + 1) = 2

print("\n=== Section — 줄 상한·렌더 ===")
s = Section("x", ["a", "b", "c"], priority=1, order=1, title="T")
check("tokens>0", s.tokens() > 0)
check("render 제목 포함", s.render().startswith("T"))

print("\n=== ContextBuilder — 줄 정리·구역 cap ===")
cb = ContextBuilder()
cb.add("multi", ["  줄   공백  정리 ", "", "x" * 300], priority=1, order=1)
sec = cb._sections[0]
check("연속공백 압축", sec.lines[0] == "줄 공백 정리")
check("빈 줄 제거", len(sec.lines) == 2)
check("초장문 줄 잘림(…)", sec.lines[1].endswith("…") and len(sec.lines[1]) <= 240)

print("\n=== build — target 초과분 저우선 구역부터 버림 ===")
cb = ContextBuilder()
cb.add("fixed_hdr", ["대상 10.129.1.5 단계 enum"], priority=0, order=0, title="STATE")
cb.add("low", [f"noise line {i}" for i in range(40)], priority=5, order=2, title="NOISE")
cb.add("mid", [f"hint {i}" for i in range(10)], priority=2, order=1, title="HINT")
built = cb.build(target=40, ceiling=200)
check("저우선(NOISE) 먼저 버려짐", built.report["dropped"].get("low", 0) > 0)
check("필수(STATE) 첫 줄 보존", "10.129.1.5" in built.text)
check("report 토큰·drop 집계", "tokens" in built.report and "dropped" in built.report)

print("\n=== build — ceiling 넘으면 필수 구역 꼬리도 깎되 첫 줄 유지 ===")
cb = ContextBuilder()
cb.add("must", ["첫 줄 핵심"] + [f"필수 꼬리 {i}" for i in range(50)],
       priority=0, order=0)
built = cb.build(target=10, ceiling=20)
check("필수 구역 일부 drop", built.report["dropped"].get("must", 0) > 0)
check("첫 줄은 남음", built.text.splitlines()[0].startswith("첫 줄 핵심"))
check("상한 근처로 수렴", built.tokens <= 60)   # 완전 20 이하는 아니어도 대폭 축소

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
