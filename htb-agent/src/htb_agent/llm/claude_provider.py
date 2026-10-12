"""Claude API 백엔드. anthropic SDK + ANTHROPIC_API_KEY 필요(지연 임포트)."""
from __future__ import annotations

import os

from .base import LLMProvider, LLMResponse, Tier


class ClaudeProvider(LLMProvider):
    name = "claude"
    # 라우터의 Deadline pause(_time_up slept 제외)용 — Claude 백엔드는 자체 백오프 대기를
    # 누적하지 않으므로 0.0 고정(일관성: 라우터가 getattr 로 읽되 명시 제공). 감사 C-minor.
    slept_sec = 0.0
    # 티어별 모델 — 비용/성능 균형
    models = {
        Tier.CHEAP: "claude-haiku-5-5",
        Tier.STANDARD: "claude-sonnet-5-5",
        Tier.STRONG: "claude-opus-5-5",
    }

    def available(self) -> tuple[bool, str]:
        import importlib.util
        if importlib.util.find_spec("anthropic") is None:
            return False, "anthropic SDK 미설치 (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY 환경변수 미설정"
        return True, "ok"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024,
                 tools: "list | None" = None) -> LLMResponse:
        # 계약: API 오류는 예외로 전파한다(HybridRouter 폴백·서킷브레이커, 오케스트레이터
        # 라운드 격리가 이 예외에 의존). 직접 호출자는 try/except 로 감쌀 것. (base.py 참고)
        import anthropic
        client = anthropic.Anthropic()
        model = self.model_for(tier)
        # 빈 content 는 Anthropic API 가 400(invalid_request_error)로 거부한다 — 호출부가
        # 빈 사용자 프롬프트를 넘기면(상태 변화 없는 라운드 등) 요청 자체가 실패하므로 가드.
        user = user if (user and user.strip()) else "(관측 없음 — 다음 열거 명령을 제안하라)"
        kwargs: dict = dict(model=model, max_tokens=max_tokens,
                            messages=[{"role": "user", "content": user}])
        # 큰 시스템 프롬프트는 prefix 캐시 대상(ephemeral) — 반복 호출서 토큰 절감.
        # 시스템이 비어있으면 블록을 넣지 않는다(빈 text 블록도 400 유발).
        if system and system.strip():
            kwargs["system"] = [{"type": "text", "text": system,
                                 "cache_control": {"type": "ephemeral"}}]
        if tools:
            # 네이티브 tool use: 첫 도구를 강제 호출 → 응답이 스키마대로 구조화된 JSON 으로 온다
            # (텍스트 파싱 취약성 제거). 결과는 tool_calls 로, 텍스트 폴백은 라우터가 처리.
            kwargs["tools"] = tools
            kwargs["tool_choice"] = {"type": "tool", "name": tools[0]["name"]}
        msg = client.messages.create(**kwargs)
        stop = getattr(msg, "stop_reason", "") or ""
        # 거절(refusal)이면 본문을 쓰지 않는다 — 라우터가 원인을 기록하고 다른 백엔드로 폴백
        text = "" if stop == "refusal" else "".join(
            getattr(b, "text", "") for b in msg.content if getattr(b, "type", "") == "text")
        tool_calls = [] if stop == "refusal" else [
            {"name": getattr(b, "name", ""), "input": getattr(b, "input", {}) or {}}
            for b in msg.content if getattr(b, "type", "") == "tool_use"]
        usage = getattr(msg, "usage", None)
        return LLMResponse(
            text, model, stop_reason=stop, tool_calls=tool_calls,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
