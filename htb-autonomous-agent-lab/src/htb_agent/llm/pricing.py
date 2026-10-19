"""
LLM 가격·비용 추정 (per 1M 토큰, USD)
======================================

Anthropic 1st-party API 요율(claude-api 스킬 기준, 2026-09 캐시). 로컬(Ollama)은
무과금(0). 가격은 변할 수 있으므로 참고용 추정이며, 정확한 청구는 콘솔을 확인.
"""

from __future__ import annotations

# {model: (input, output, cache_read)} — $/1M 토큰
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-haiku-4-5": (1.00, 5.00, 0.10),
    "claude-fable-5-1": (10.00, 50.00, 1.00),
}

CACHE_WRITE_MULT = 1.25   # 캐시 생성은 입력가의 1.25배(통상)


def _price_for(model: str) -> tuple[float, float, float] | None:
    """정확 일치 → 가장 긴 접두사 일치. 날짜 접미사 ID(claude-haiku-4-5-2025…)가
    '미등록 = 무료'로 조용히 0 원 처리되는 것을 막는다."""
    if model in PRICES:
        return PRICES[model]
    best = max((k for k in PRICES if model.startswith(k)), key=len, default=None)
    return PRICES[best] if best else None


def is_paid(model: str) -> bool:
    """과금 모델인가(로컬/미등록은 아님). 토큰 예산은 과금 모델만 센다."""
    return _price_for(model) is not None


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int,
                  cache_read_tokens: int = 0, cache_creation_tokens: int = 0) -> float:
    """토큰 사용량으로 비용(USD) 추정. 미등록 모델(로컬 등)은 0.

    `prompt_tokens` 는 Anthropic `usage.input_tokens` — **캐시를 제외한 나머지**
    입력이다. 전체 입력 = prompt + cache_read + cache_creation. 캐시 토큰을 여기서
    또 빼면 비캐시 입력 요금이 사라져 비용이 과소 추정된다(캐시를 켜면 켤수록 커짐).
    """
    price = _price_for(model)
    if not price:
        return 0.0
    pin, pout, pcache = price
    cost = (prompt_tokens * pin
            + cache_read_tokens * pcache
            + cache_creation_tokens * pin * CACHE_WRITE_MULT
            + completion_tokens * pout) / 1_000_000
    return round(cost, 6)
