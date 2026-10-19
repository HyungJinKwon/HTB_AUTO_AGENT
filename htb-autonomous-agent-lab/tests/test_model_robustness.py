# 실행: htb-agent 디렉토리에서  python3 tests/test_model_robustness.py
# Opus → Sonnet → 로컬 모델로 바뀌어도 파이프라인이 버티는가. 명령은 전부 무해한 확인 명령.
import io
import json
import os
import sys
import types
import urllib.request

sys.path.insert(0, "src")
from htb_agent.llm.base import LLMProvider, LLMResponse, Tier
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter, BudgetExhausted, strip_reasoning, is_none
from htb_agent.llm.claude_provider import ClaudeProvider
from htb_agent.llm.ollama_provider import OllamaProvider
from htb_agent.tiering import HybridProvider

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.10"
GOOD = f"CMD curl -s http://{T}/robots.txt ||| probe:curl -s http://{T}/robots.txt::Disallow"


def parse(text, allow_shell=False, limit=10):
    return LLMRouter._parse_candidates(strip_reasoning(text), T, "access", limit, allow_shell)


print("=== 약한 모델의 출력 변형을 받아들인다 ===")
check("정규형", len(parse(GOOD)) == 1)
check("마크다운 펜스 + 번호", len(parse("```\n1. " + GOOD + "\n```")) == 1)
check("불릿 + 볼드", len(parse("- **" + GOOD + "**")) == 1)
check("'Command:' 라벨", len(parse("Command: " + GOOD.replace("CMD ", ""))) == 1)
check("구분자 '=>' (오른쪽이 유효한 expected 일 때)",
      len(parse(f"CMD curl -s http://{T}/a => probe:curl -s http://{T}/a::ok")) == 1)
check("구분자 '->'", len(parse(f"CMD curl -s http://{T}/a -> probe:curl -s http://{T}/a::ok")) == 1)
check("'expected:' 라벨", len(parse(f"CMD curl -s http://{T}/a ||| expected: probe:curl -s http://{T}/a::ok")) == 1)
check("대문자 'Probe:' 와 '::' 주위 공백",
      parse(f"CMD curl -s http://{T}/a ||| Probe: curl -s http://{T}/a :: ok")[0].expected
      == f"probe:curl -s http://{T}/a :: ok")
c = parse(f"CMD curl -s http://{{t}}/a ||| probe:curl -s http://{{t}}/a::ok")[0]
check("{t} 는 명령과 expected 양쪽에서 치환", T in c.commands[0] and T in c.expected and "{t}" not in c.expected)
check("명령 안의 파이프는 보존",
      parse(f"CMD ps aux | grep ssh ||| probe:curl -s http://{T}/p::ok")[0].commands[0] == "ps aux | grep ssh")
check("중복 제거", len(parse(GOOD + "\n" + GOOD)) == 1)
check("상한 적용", len(parse("\n".join(
    f"CMD curl -s http://{T}/{i} ||| probe:curl -s http://{T}/{i}::ok" for i in range(9)), limit=3)) == 3)

print("=== 받아들인 뒤의 의미는 여전히 엄격하다 ===")
check("자연어 expected 는 버린다", parse(f"CMD curl -s http://{T}/a ||| 셸이 열릴 것") == [])
check("expected 없는 줄은 버린다", parse("CMD curl -s http://x/a") == [])
check("산문 줄 + 파이프 오인 없음(오른쪽이 규약 밖이면 분리 안 함)",
      parse(f"CMD curl -s http://{T}/a -> returns a page") == [])
check("shell: 은 채널 없이는 버린다", parse(f"CMD nc {T} 21 ||| shell:ftp") == [])
check("shell: 은 채널 있으면 허용", len(parse(f"CMD nc {T} 21 ||| shell:ftp", allow_shell=True)) == 1)
check("grants 의 콜론은 제거(접두사 위장 불가)",
      parse(GOOD + " ||| flag:user")[0].grants == "flaguser")

print("=== 추론형 모델의 <think> 블록 ===")
decoy = f"CMD curl -s http://{T}/decoy ||| probe:curl -s http://{T}/decoy::ok"
check("<think> 안의 시안 줄은 답이 아니다",
      parse(f"<think>\nmaybe {decoy}\n</think>\n{GOOD}")[0].commands[0].endswith("/robots.txt"))
check("<think> 안에만 있으면 후보 0", parse(f"<think>{decoy}</think>") == [])
cmds = lambda cs: [c.commands for c in cs]
check("닫히지 않은 <think>(출력 잘림)는 통째로 버림",
      cmds(parse(f"{GOOD}\n<think>I should {decoy}")) == cmds(parse(GOOD)) != [])
check("strip_reasoning 단독", strip_reasoning("<think>a</think>b") == "b")
check("NONE 인식", is_none("NONE") and is_none(" none. ") and not is_none("nonexistent cmd"))
check("열거 파서도 <think>/NONE 처리",
      LLMRouter._parse("<think>nmap -sV {t}</think>\nNONE", T, 5) == [])


print("=== 형식 위반 → 1회 복구 → 연속 실패 시 티어 상승 ===")
class Seq(LLMProvider):
    """호출마다 정해진 응답을 돌려주고, 받은 티어/max_tokens/프롬프트를 기록한다."""
    name = "seq"
    models = {Tier.CHEAP: "llama3.1:8b", Tier.STANDARD: "llama3.1:8b", Tier.STRONG: "llama3.1:70b"}
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []
    def complete(self, system, user, tier=Tier.STANDARD, max_tokens=1024):
        self.calls.append((tier, max_tokens, user))
        r = self.replies.pop(0) if self.replies else "I cannot decide."
        return r if isinstance(r, LLMResponse) else LLMResponse(r, self.model_for(tier))

p = Seq(["Sure! Here are some ideas you could try.", GOOD])
rt = LLMRouter(p, default_tier=Tier.CHEAP)
out = rt.suggest_candidates({}, T, "access")
check("복구 재요청으로 후보 확보", len(out) == 1 and len(p.calls) == 2)
check("재요청에 형식 안내와 예시가 붙음", "FORMAT ERROR" in p.calls[1][2] and "CMD " in p.calls[1][2])
check("복구 성공이면 건강도 리셋", rt.fail_streak == 0 and rt.tier_bias == 0)

p = Seq(["no idea", "still prose", "nope", "nothing"])
rt = LLMRouter(p, default_tier=Tier.CHEAP)
check("복구도 실패하면 빈 목록", rt.suggest_candidates({}, T, "access") == [] and len(p.calls) == 2)
check("호출당 복구는 최대 1회(= 총 2호출)", len(p.calls) == 2)
rt.suggest_candidates({}, T, "access")
check("연속 형식 실패 2회 → 티어 한 단계 상승", rt.tier_bias == 1)
rt.suggest_candidates({}, T, "access")
check("상승한 티어로 호출됨", p.calls[-1][0] == Tier.STANDARD)

p = Seq(["NONE"])
rt = LLMRouter(p, default_tier=Tier.CHEAP)
check("NONE 은 정상 — 복구 호출 없음", rt.suggest_candidates({}, T, "access") == [] and len(p.calls) == 1)
check("NONE 은 실패로 세지 않음", rt.fail_streak == 0)

print("=== 잘림(max_tokens)은 '아이디어 없음'이 아니다 ===")
p = Seq([LLMResponse("", "llama3.1:8b", finish="truncated"), GOOD])
rt = LLMRouter(p, default_tier=Tier.CHEAP)
out = rt.suggest_candidates({}, T, "access")
check("잘렸으면 출력 한도를 키워 재시도", len(out) == 1 and p.calls[1][1] > p.calls[0][1])

print("=== 거절은 정책 판단 — 우회 재시도·티어 상승 없음 ===")
p = Seq([LLMResponse("", "claude-sonnet-5-5", finish="refused", detail="cyber")])
rt = LLMRouter(p, default_tier=Tier.STANDARD)
check("거절이면 빈 목록", rt.suggest_candidates({}, T, "access") == [])
check("재요청하지 않음(1호출)", len(p.calls) == 1)
check("거절 집계", rt.refusals == 1 and "거절 1회" in rt.cost_summary())
check("거절은 형식 실패가 아니므로 티어를 올리지 않음", rt.tier_bias == 0 and rt.fail_streak == 0)
for _ in range(3):
    p.replies.append(LLMResponse("", "claude-sonnet-5-5", finish="refused", detail="cyber"))
    rt.suggest_candidates({}, T, "access")
check("거절이 반복돼도 티어 상승 없음", rt.tier_bias == 0)

print("=== 토큰 예산: 과금 모델만 센다 ===")
def paid(n_in, n_out, model="claude-sonnet-5-5"):
    return LLMResponse("NONE", model, prompt_tokens=n_in, completion_tokens=n_out)
p = Seq([paid(600, 100), paid(300, 100), paid(10, 10)])
rt = LLMRouter(p, token_budget=1000)
rt.suggest_candidates({}, T, "x")
check("누적 집계", rt.paid_tokens == 700 and not rt.exhausted())
rt.suggest_candidates({}, T, "x")
check("예산 도달", rt.exhausted())
try:
    rt.suggest_candidates({}, T, "x"); ok = False
except BudgetExhausted:
    ok = True
check("소진 후 호출은 막힘(BudgetExhausted)", ok and len(p.calls) == 2)
p = Seq([paid(10**6, 10**6, model="llama3.1:8b")])
rt = LLMRouter(p, token_budget=100)
rt.suggest_candidates({}, T, "x")
check("로컬 모델은 예산에 안 센다", rt.paid_tokens == 0 and not rt.exhausted())
p = Seq([LLMResponse("NONE", "claude-sonnet-5-5", prompt_tokens=100, cache_read_tokens=400,
                     cache_creation_tokens=200, completion_tokens=50)])
rt = LLMRouter(p, token_budget=10**6)
rt.suggest_candidates({}, T, "x")
check("예산은 캐시 토큰도 포함(입력 총량)", rt.paid_tokens == 750)

print("=== 로컬 창이 찼다 → 컨텍스트 예산 축소 ===")
p = Seq([LLMResponse("NONE", "llama3.1:8b", detail="ctx_full")])
rt = LLMRouter(p, default_tier=Tier.CHEAP)
before = rt._profile(Tier.CHEAP).target
rt.suggest_candidates({}, T, "x")
check("ctx_full 이면 배율 축소", rt.ctx_scale < 1.0 and rt._profile(Tier.CHEAP).target < before)


print("=== Claude 프로바이더(문서 기준 스텁) ===")
def stub_anthropic(handler):
    m = types.ModuleType("anthropic")
    class APIStatusError(Exception):
        def __init__(self, status_code=500):
            super().__init__(f"status {status_code}"); self.status_code = status_code
    class NotFoundError(APIStatusError):
        def __init__(self): super().__init__(404)
    class _Messages:
        def create(self, **kw): return handler(kw)
    class Anthropic:
        def __init__(self, *a, **k): self.messages = _Messages()
    m.APIStatusError, m.NotFoundError, m.Anthropic = APIStatusError, NotFoundError, Anthropic
    return m

def msg(text="ok", stop="end_turn", usage=(100, 20, 0, 0), details=None):
    u = types.SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1],
                              cache_read_input_tokens=usage[2], cache_creation_input_tokens=usage[3])
    return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=text)],
                                 usage=u, stop_reason=stop, stop_details=details)

def with_stub(handler, fn):
    old = sys.modules.get("anthropic")
    sys.modules["anthropic"] = stub_anthropic(handler)
    try:
        return fn()
    finally:
        if old is None: sys.modules.pop("anthropic", None)
        else: sys.modules["anthropic"] = old

seen_kw = []
def h_ok(kw):
    seen_kw.append(kw); return msg("hello")
cp = ClaudeProvider()
r = with_stub(h_ok, lambda: cp.complete("sys", "usr", Tier.STRONG, 8000))
kw = seen_kw[-1]
check("STRONG → Opus", kw["model"] == "claude-opus-5-5" and r.model == "claude-opus-5-5")
check("티어→effort(high)", kw["output_config"] == {"effort": "high"})
check("max_tokens 전달", kw["max_tokens"] == 8000)
check("시스템 프롬프트는 캐시 표시", kw["system"][0]["cache_control"] == {"type": "ephemeral"})
check("5.x 에서 거부되는 파라미터를 보내지 않음",
      not ({"thinking", "temperature", "top_p", "top_k", "budget_tokens"} & set(kw)))
with_stub(h_ok, lambda: cp.complete("s", "u", Tier.STANDARD, 8000))
check("STANDARD → Sonnet, effort medium",
      seen_kw[-1]["model"] == "claude-sonnet-5-5" and seen_kw[-1]["output_config"] == {"effort": "medium"})
with_stub(h_ok, lambda: cp.complete("s", "u", Tier.CHEAP, 1536))
check("Haiku 4.5 에는 effort 를 보내지 않음(오류 방지)",
      seen_kw[-1]["model"] == "claude-haiku-4-5" and "output_config" not in seen_kw[-1])

r = with_stub(lambda kw: msg("x", usage=(100, 20, 900, 50)), lambda: cp.complete("s", "u"))
check("usage 매핑: input_tokens 는 비캐시분", r.prompt_tokens == 100 and r.cache_read_tokens == 900
      and r.cache_creation_tokens == 50 and r.completion_tokens == 20)
r = with_stub(lambda kw: msg("", stop="refusal", details=types.SimpleNamespace(category="cyber")),
              lambda: cp.complete("s", "u"))
check("refusal → finish=refused, 본문 비움, 분류 보존",
      r.finish == "refused" and r.text == "" and r.detail == "cyber")
r = with_stub(lambda kw: msg("partial", stop="max_tokens"), lambda: cp.complete("s", "u"))
check("max_tokens → finish=truncated", r.finish == "truncated")

# 가용성 폴백: 모델 없음(404) / 과부하(529) → 한 칸씩 내려가고, 실제 응답 모델명이 실린다
tried = []
def h_404(kw):
    tried.append(kw["model"])
    if kw["model"] in ("claude-opus-5-5", "claude-opus-5"):
        raise sys.modules["anthropic"].NotFoundError()
    return msg("from sonnet")
r = with_stub(h_404, lambda: cp.complete("s", "u", Tier.STRONG))
check("Opus 없음 → Opus5 → Sonnet 으로 내려감", tried == ["claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"])
check("응답 모델명은 실제로 답한 모델", r.model == "claude-sonnet-5-5")
tried2 = []
def h_529(kw):
    tried2.append(kw)
    if kw["model"] == "claude-opus-5-5":
        raise sys.modules["anthropic"].APIStatusError(529)
    return msg("ok")
with_stub(h_529, lambda: cp.complete("s", "u", Tier.STRONG))
check("폴백 모델에도 STRONG 의 effort(high) 적용(능력 하락 보정)",
      tried2[-1]["model"] == "claude-opus-5" and tried2[-1]["output_config"] == {"effort": "high"})
def h_400(kw): raise sys.modules["anthropic"].APIStatusError(400)
try:
    with_stub(h_400, lambda: cp.complete("s", "u")); raised = False
except Exception as e:
    raised = getattr(e, "status_code", 0) == 400
check("400 은 폴백으로 못 푼다 — 그대로 올린다", raised)
def h_all(kw): raise sys.modules["anthropic"].NotFoundError()
try:
    with_stub(h_all, lambda: cp.complete("s", "u", Tier.STANDARD)); raised = False
except Exception:
    raised = True
check("체인이 모두 실패하면 마지막 오류", raised)


print("=== Ollama 프로바이더(urlopen 대체) ===")
class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False

def with_urlopen(payload, fn):
    sent = {}
    def fake(req, timeout=0):
        sent["body"] = json.loads(req.data.decode()) if getattr(req, "data", None) else None
        return _Resp(json.dumps(payload).encode())
    old = urllib.request.urlopen
    urllib.request.urlopen = fake
    try:
        return fn(), sent
    finally:
        urllib.request.urlopen = old

op = OllamaProvider(num_ctx=8192)
r, sent = with_urlopen({"response": "hi", "prompt_eval_count": 500, "eval_count": 30},
                       lambda: op.complete("s", "u", Tier.STANDARD, 1536))
o = sent["body"]["options"]
check("num_ctx 를 명시해서 보낸다(조용한 앞부분 절단 방지)", o["num_ctx"] == 8192)
check("num_predict/온도 전달", o["num_predict"] == 1536 and o["temperature"] <= 0.3)
check("토큰 수를 돌려준다", r.prompt_tokens == 500 and r.completion_tokens == 30)
check("정상이면 finish=ok", r.finish == "ok" and r.detail == "")
r, _ = with_urlopen({"response": "x", "done_reason": "length", "prompt_eval_count": 10, "eval_count": 1536},
                    lambda: op.complete("s", "u"))
check("done_reason=length → truncated", r.finish == "truncated")
r, _ = with_urlopen({"response": "x", "prompt_eval_count": 8100, "eval_count": 5},
                    lambda: op.complete("s", "u"))
check("프롬프트가 창을 채웠으면 ctx_full 표시", "ctx_full" in r.detail)
os.environ["HTB_OLLAMA_STANDARD"] = "qwen2.5-coder:32b"
os.environ["HTB_OLLAMA_NUM_CTX"] = "16384"
try:
    op2 = OllamaProvider()
    check("모델명은 환경변수로 지정('소넷급' 로컬)", op2.model_for(Tier.STANDARD) == "qwen2.5-coder:32b")
    check("창도 환경변수로", op2.num_ctx == 16384 and op2.num_ctx_for(Tier.STANDARD) == 16384)
finally:
    os.environ.pop("HTB_OLLAMA_STANDARD"); os.environ.pop("HTB_OLLAMA_NUM_CTX")
check("기본 창 8192", OllamaProvider().num_ctx == 8192)


print("=== 하이브리드: '이 티어는 누가 처리하나'에 맞게 답한다 ===")
class Loc(FakeProvider):
    name = "ollama"; models = {Tier.CHEAP: "llama3.1:8b", Tier.STANDARD: "llama3.1:8b", Tier.STRONG: "llama3.1:70b"}
    def num_ctx_for(self, tier): return 8192
class Ext(FakeProvider):
    name = "claude"; models = {Tier.CHEAP: "claude-haiku-4-5", Tier.STANDARD: "claude-sonnet-5-5", Tier.STRONG: "claude-opus-5-5"}
h = HybridProvider(local=Loc("L"), external=Ext("E"))
check("CHEAP 은 로컬 모델명(병합 dict 의 Claude 모델명이 아님)", h.model_for(Tier.CHEAP) == "llama3.1:8b")
check("STRONG 은 외부 모델명", h.model_for(Tier.STRONG) == "claude-opus-5-5")
check("로컬 티어는 로컬 창", h.num_ctx_for(Tier.CHEAP) == 8192)
check("외부 티어는 창 제약 없음", h.num_ctx_for(Tier.STRONG) is None)
rt = LLMRouter(h, default_tier=Tier.CHEAP)
check("라우터가 티어별로 올바른 프로필을 고른다",
      rt._profile(Tier.CHEAP).klass == "low" and rt._profile(Tier.STRONG).klass == "high")

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
