"""테스트/오프라인용 가짜 프로바이더 — API 키·네트워크 불필요."""
from __future__ import annotations

from typing import Callable
from .base import LLMProvider, LLMResponse, Tier


class FakeProvider(LLMProvider):
    name = "fake"
    models = {Tier.CHEAP: "fake-cheap", Tier.STANDARD: "fake-std", Tier.STRONG: "fake-strong"}

    def __init__(self, text_or_fn: "str | Callable[[str, str, Tier], str]"):
        self._r = text_or_fn

    def available(self) -> tuple[bool, str]:
        return True, "fake"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        out = self._r(system, user, tier) if callable(self._r) else self._r
        if isinstance(out, LLMResponse):   # responder 가 usage 포함 응답을 줄 수 있음
            return out
        return LLMResponse(text=out, model=self.model_for(tier))
