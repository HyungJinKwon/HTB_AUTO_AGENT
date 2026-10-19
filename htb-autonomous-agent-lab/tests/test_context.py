# 실행: htb-agent 디렉토리에서  python3 tests/test_context.py
# 컨텍스트 예산·우선순위·'채우지 않기' + 모델 프로필.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.context import ContextBuilder, est_tokens
from htb_agent.llm.router import LLMRouter, ENUM_PROMPT
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.base import Tier
from htb_agent.tiering import profile_for

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== 토큰 추정(보수적) ===")
check("빈 문자열 0", est_tokens("") == 0)
check("한글은 영문보다 토큰 밀도가 높다", est_tokens("가나다라마바사아자차") > est_tokens("abcdefghij"))
check("길수록 단조 증가", est_tokens("a" * 300) > est_tokens("a" * 30))
check("ASCII 3자/토큰 이하로 과소추정하지 않음", est_tokens("a" * 300) >= 100)


print("=== 채우지 않는다: 목표 아래에서는 아무것도 덜어내지 않고 패딩도 없다 ===")
b = ContextBuilder()
b.add("task", ["Target: 10.0.0.1"], priority=0, order=0)
b.add("kb", ["rule A: cmd a", "rule B: cmd b"], priority=3, order=1, title="KB:")
small = b.build(target=4000, ceiling=8000)
check("아무것도 안 덜어냄", small.report["dropped"] == {})
check("토큰은 실제 내용만큼(목표보다 훨씬 작음)", small.tokens < 100)
check("목표 초과 아님", not small.report["over_target"])


print("=== 우선순위: 낮은 것부터 버리고 필수는 남긴다 ===")
def fat():
    b = ContextBuilder()
    b.add("task", ["Target: 10.0.0.1", "Phase: access"], priority=0, order=0)
    b.add("dead", [f"failed idea {i}: reason {i}" for i in range(6)], priority=1, order=90, title="Dead:")
    b.add("findings", [f"obs {i}: " + "x" * 120 for i in range(12)], priority=2, order=80, title="Obs:")
    b.add("kb", [f"rule {i}: " + "y" * 120 for i in range(8)], priority=3, order=41, title="KB:")
    b.add("notes", ["note " + "z" * 200], priority=4, order=60, title="Notes:")
    b.add("ask", ["Propose."], priority=0, order=100)
    return b
full = fat().build(target=10**9, ceiling=10**9)
tight = fat().build(target=full.tokens // 2, ceiling=10**9)
check("목표 이하로 줄어듦", tight.tokens <= full.tokens // 2)
check("가장 낮은 우선순위(notes)가 먼저 사라짐", "notes" not in tight.report["kept"])
check("필수(task/ask) 유지", "task" in tight.report["kept"] and "ask" in tight.report["kept"])
check("실패한 가설(P1)은 가능한 한 보존", tight.report["kept"].get("dead", 0) == 6)
check("drop 기록", tight.report["dropped"].get("notes", 0) >= 1)
very = fat().build(target=60, ceiling=10**9)
check("극단적으로 빠듯해도 필수는 남음", "Target: 10.0.0.1" in very.text and "Propose." in very.text)
check("극단적이면 P1 도 잘려 나감", very.report["kept"].get("dead", 0) < 6)

print("=== 구역 안에서는 꼬리(덜 중요한 줄)부터 ===")
b = ContextBuilder()
b.add("findings", [f"newest-first line {i}" for i in range(10)], priority=2, order=1)
r = b.build(target=40, ceiling=10**9)
check("첫 줄(가장 중요)은 남는다", "newest-first line 0" in r.text)
check("마지막 줄은 먼저 사라진다", "newest-first line 9" not in r.text)
check("생략 표시가 붙는다", "omitted" in r.text)

print("=== 구역 상한(cap) / 줄 상한 ===")
b = ContextBuilder()
b.add("notes", ["n" * 200] * 6, priority=4, order=1, cap=120)
r = b.build(target=10**9, ceiling=10**9)
check("cap 으로 줄 수 제한", r.report["kept"]["notes"] < 6 and r.report["dropped"]["notes"] > 0)
b = ContextBuilder(max_line_chars=50)
b.add("x", ["A" * 500], priority=0, order=0)
check("한 줄이 폭주해도 줄 상한", len(b.build(10**9, 10**9).text) < 80)

print("=== 우선순위와 렌더 순서는 독립 ===")
b = ContextBuilder()
b.add("late", ["LATE"], priority=0, order=90)
b.add("early", ["EARLY"], priority=4, order=1)
t = b.build(10**9, 10**9).text
check("order 가 작은 구역이 앞에", t.index("EARLY") < t.index("LATE"))

print("=== 시스템 프롬프트(fixed)는 예산에서 먼저 빠진다 ===")
mk = lambda: [("a", ["x" * 100] * 4)]
b1, b2 = ContextBuilder(), ContextBuilder()
for b in (b1, b2):
    b.add("kb", ["line " + "k" * 80] * 6, priority=3, order=1)
r1 = b1.build(target=300, ceiling=10**9, fixed=0)
r2 = b2.build(target=300, ceiling=10**9, fixed=250)
check("fixed 가 크면 user 몫이 줄어든다", r2.report["kept"].get("kb", 0) < r1.report["kept"].get("kb", 0))
check("총량은 fixed 포함 목표 이하", r2.tokens <= 300)

print("=== 빈 구역은 제목도 렌더하지 않는다 ===")
b = ContextBuilder()
b.add("empty", [], priority=2, order=1, title="SHOULD NOT APPEAR")
b.add("task", ["T"], priority=0, order=0)
check("빈 구역 제목 없음", "SHOULD NOT APPEAR" not in b.build(100, 200).text)


print("=== 모델 프로필: 어떤 모델이 들어와도 예산이 맞는다 ===")
P = profile_for
check("Opus → high", P("claude-opus-5-5").klass == "high")
check("Sonnet → mid", P("claude-sonnet-5-5").klass == "mid")
check("Haiku → low", P("claude-haiku-4-5").klass == "low")
check("날짜 접미사 Haiku → low", P("claude-haiku-4-5-20251001").klass == "low")
check("알 수 없는 claude-* → mid(보수적)", P("claude-future-9").klass == "mid")
check("로컬 70B → mid(소넷급)", P("llama3.3:70b", 8192).klass == "mid")
check("로컬 32B → mid", P("qwen2.5-coder:32b", 16384).klass == "mid")
check("로컬 8B → low", P("llama3.1:8b", 8192).klass == "low")
check("MoE 8x7b → mid", P("mixtral:8x7b", 8192).klass == "mid")
check("이름만으로 모르면 low", P("mystery-model").klass == "low")
check("약할수록 목표 토큰이 작다",
      P("claude-opus-5-5").target > P("claude-sonnet-5-5").target > P("claude-haiku-4-5").target)
check("약할수록 요청 후보 수가 적다",
      P("claude-opus-5-5").items > P("claude-sonnet-5-5").items > P("claude-haiku-4-5").items)
check("약할수록 형식 예시가 많다",
      P("claude-opus-5-5").fewshot < P("claude-sonnet-5-5").fewshot < P("claude-haiku-4-5").fewshot)
check("사고형 로컬은 출력 한도가 크다", P("deepseek-r1:8b", 32768).max_out > P("llama3.1:8b", 32768).max_out)
small_ctx = P("llama3.3:70b", 4096)
check("로컬 창이 작으면 목표/상한이 창에 맞춰 줄어든다",
      small_ctx.ceiling <= int(4096 * 0.6) and small_ctx.target <= int(4096 * 0.35))
check("출력 공간이 창 안에 남는다", small_ctx.ceiling + small_ctx.max_out <= 4096 + 256)
check("Claude 는 창 파라미터를 무시", P("claude-opus-5-5", 2048).target == P("claude-opus-5-5").target)


print("=== 라우터가 프로필 예산 안에서만 조립한다 ===")
big_ctx = {
    "phase": "Initial Access", "profile": "Linux (high)\nhyp a\nhyp b\nhyp c",
    "open_ports": [f"{p}/tcp open svc{p}" for p in range(20, 60)],
    "kb": [f"rule {i}: curl -s http://{{t}}/p{i} ; ffuf -u http://{{t}}/FUZZ" for i in range(12)],
    "cve": [f"vuln {i}: CVE-2020-{1000+i} -> tool" for i in range(8)],
    "clues": [f"host: h{i}.corp.htb" for i in range(10)],
    "notes": ["note " + "n" * 400] * 3,
    "findings": [f"cmd{i} => " + "out " * 60 for i in range(40)],
    "dead": [f"idea {i}: failed because {i}" for i in range(20)],
}
for model, label in [("claude-opus-5-5", "high"), ("claude-sonnet-5-5", "mid"), ("llama3.1:8b", "low")]:
    class P1(FakeProvider):
        models = {Tier.CHEAP: model, Tier.STANDARD: model, Tier.STRONG: model}
    rt = LLMRouter(P1("NONE"))
    prof = rt._profile(Tier.STANDARD)
    system = ENUM_PROMPT.replace("{items}", "3")
    user = rt._build_user(big_ctx, "10.0.0.1", prof, system, "Propose.")
    total = est_tokens(system) + est_tokens(user)
    check(f"{label}: 큰 컨텍스트도 목표({prof.target}) 이하로 조립", total <= prof.target + 40)
    check(f"{label}: 필수 정보(대상·요청) 유지", "Target: 10.0.0.1" in user and "Propose." in user)

sizes = {}
for model in ("claude-opus-5-5", "llama3.1:8b"):
    class P2(FakeProvider):
        models = {Tier.CHEAP: model, Tier.STANDARD: model, Tier.STRONG: model}
    rt = LLMRouter(P2("NONE"))
    sizes[model] = est_tokens(rt._build_user(big_ctx, "10.0.0.1", rt._profile(Tier.STANDARD),
                                             ENUM_PROMPT, "Propose."))
check("low 프롬프트 < high 프롬프트", sizes["llama3.1:8b"] < sizes["claude-opus-5-5"])

# 최신 관측이 먼저, 오래된 것이 먼저 사라진다
class P3(FakeProvider):
    models = {Tier.CHEAP: "llama3.1:8b", Tier.STANDARD: "llama3.1:8b", Tier.STRONG: "llama3.1:8b"}
rt = LLMRouter(P3("NONE"))
user = rt._build_user({"findings": [f"obs-{i} => " + "x" * 100 for i in range(40)]},
                      "10.0.0.1", rt._profile(Tier.STANDARD), ENUM_PROMPT, "Propose.")
check("최신 관측(obs-39)은 남는다", "obs-39" in user)
check("가장 오래된 관측(obs-0)은 먼저 사라진다", "obs-0 =>" not in user)

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
