"""Claude API 백엔드. anthropic SDK + ANTHROPIC_API_KEY 필요(지연 임포트).

모델이 바뀌어도(Opus → Sonnet → Haiku, 또는 폴백) 호출부가 깨지지 않게 하는 것이 목적:

  - **effort 는 모델이 아니라 티어에 묶는다.** Opus 가 빠져 Sonnet 이 STRONG 을 맡아도
    '더 오래 생각'(high)으로 능력 하락을 보정한다. Haiku 4.5 는 effort 를 보내면 오류라 제외.
  - **max_tokens 에 사고 토큰이 포함된다.** Opus 5.5·Sonnet 5.5 는 `thinking` 을 생략하면
    적응형 사고가 기본으로 켜지고, 기본 effort 도 Opus=medium / Sonnet=high 로 다르다.
    1024 같은 작은 한도는 사고에 다 쓰여 본문이 비거나 잘린다 → 호출부(라우터)가 넉넉히 준다.
  - **거절(refusal)과 잘림(max_tokens)은 예외가 아니라 HTTP 200** 이다. 종료 사유를
    `LLMResponse.finish` 로 올려, 호출부가 '아이디어 없음'과 구분하게 한다.
  - 모델이 없거나(404) 서버 과부하(5xx, SDK 재시도 소진 후)면 `fallbacks` 체인에서 한 칸씩
    내려간다. 실제로 응답한 모델명이 `LLMResponse.model` 에 실려 비용·예산이 거기에 맞는다.
"""
from __future__ import annotations

import os
from .base import LLMProvider, LLMResponse, Tier

# effort 파라미터를 받는 모델 접두사(문서 기준). Haiku 4.5 는 받지 않는다.
_EFFORT_MODELS = ("claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
                  "claude-sonnet-5", "claude-sonnet-4-6", "claude-fable", "claude-mythos")
_EFFORT = {Tier.CHEAP: "low", Tier.STANDARD: "medium", Tier.STRONG: "high"}


class ClaudeProvider(LLMProvider):
    name = "claude"
    # 티어별 모델 — 비용/성능 균형
    models = {
        Tier.CHEAP: "claude-haiku-4-5",
        Tier.STANDARD: "claude-sonnet-5-5",
        Tier.STRONG: "claude-opus-5-5",
    }
    # 정책 거절이 아닌 '가용성' 문제일 때만 내려간다(아래 complete 참조).
    fallbacks: dict[str, list[str]] = {
        "claude-opus-5-5": ["claude-opus-5", "claude-sonnet-5-5"],
        "claude-sonnet-5-5": ["claude-sonnet-5"],
    }

    def available(self) -> tuple[bool, str]:
        import importlib.util
        if importlib.util.find_spec("anthropic") is None:
            return False, "anthropic SDK 미설치 (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY 환경변수 미설정"
        return True, "ok"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        import anthropic
        client = anthropic.Anthropic()
        primary = self.model_for(tier)
        chain = [primary] + [m for m in self.fallbacks.get(primary, []) if m != primary]
        last: Exception | None = None
        for model in chain:
            try:
                return self._call(client, model, system, user, tier, max_tokens)
            except anthropic.NotFoundError as e:          # 모델 없음/퇴역
                last = e
            except anthropic.APIStatusError as e:
                if getattr(e, "status_code", 0) >= 500:   # 529 과부하 포함
                    last = e
                else:
                    raise                                  # 400/401/403 등은 폴백으로 못 푼다
        assert last is not None
        raise last

    @staticmethod
    def _call(client, model: str, system: str, user: str,
              tier: Tier, max_tokens: int) -> LLMResponse:
        # 큰 시스템 프롬프트는 prefix 캐시 대상(ephemeral). 최소 캐시 길이(모델별
        # 512~4096 토큰)보다 짧으면 조용히 무시된다 — 그래서 시스템 프롬프트는
        # '정적으로' 유지하고 변하는 값은 전부 user 쪽에 둔다.
        kwargs = dict(
            model=model, max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
        if model.startswith(_EFFORT_MODELS):
            kwargs["output_config"] = {"effort": _EFFORT[tier]}
        msg = client.messages.create(**kwargs)

        usage = getattr(msg, "usage", None)
        counts = dict(
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,           # 비캐시분
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
        stop = getattr(msg, "stop_reason", None)
        if stop == "refusal":
            # 분류기/모델의 정책 판단. 부분 출력은 버리고, 다른 모델로 우회 재시도하지
            # 않는다 — 장애(가용성)가 아니라 정책이므로 호출부가 '거절'로 기록·보고한다.
            cat = getattr(getattr(msg, "stop_details", None), "category", None)
            return LLMResponse("", model, finish="refused", detail=str(cat or ""), **counts)
        text = "".join(getattr(b, "text", "") for b in msg.content
                       if getattr(b, "type", "") == "text")
        finish = "truncated" if stop == "max_tokens" else "ok"
        return LLMResponse(text, model, finish=finish, **counts)
