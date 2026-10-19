"""
LLM Provider 추상화 + 티어링
=============================

백엔드(Claude/Ollama)를 설정으로 교체 가능하게 하는 공통 인터페이스.
티어링으로 작업 난이도에 따라 저렴/표준/고성능 모델을 선택해 비용·토큰을 억제한다.

⚠️ 안전: LLM 출력은 '신뢰하지 않는 데이터'다. 여기서 생성된 어떤 명령도
오케스트레이터의 검증→범위→승인 3관문을 반드시 통과해야 실행된다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class Tier(str, Enum):
    CHEAP = "cheap"        # 라우틴 판단
    STANDARD = "standard"  # 일반 추론
    STRONG = "strong"      # 어려운 계획/exploit 설계


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int = 0          # 비캐시 입력 토큰
    completion_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    # 종료 사유 — 'ok' | 'truncated'(출력/사고가 한도에 막힘) | 'refused'(모델·분류기 거절).
    # 거절은 HTTP 200 으로 오고 본문이 비어, 확인하지 않으면 "아이디어 없음"으로 오인된다.
    finish: str = "ok"
    detail: str = ""        # 거절 분류, ctx_full 등 부가 사유


class LLMProvider(ABC):
    name: str = "base"
    models: dict[Tier, str] = {}

    def model_for(self, tier: Tier) -> str:
        if tier in self.models:
            return self.models[tier]
        return next(iter(self.models.values()), "")

    def available(self) -> tuple[bool, str]:
        """(사용가능?, 사유). 기본 True."""
        return True, "ok"

    def num_ctx_for(self, tier: Tier) -> int | None:
        """이 티어가 실제로 쓸 컨텍스트 창(알 수 있을 때만). 로컬 모델 예산 산정용."""
        return None

    @abstractmethod
    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        ...
