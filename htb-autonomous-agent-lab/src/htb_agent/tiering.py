"""
tiering — 난이도별 모델 차등 선택 (룰 [2-5])
=============================================

작업 난이도에 따라 저렴/로컬 모델과 고성능/외부 API 를 갈라 쓴다. 목적은
**API 토큰 소모 억제**다 — 일상적인 열거는 로컬·저렴 모델이 처리하고, 어려운
추론(침투·권한상승)과 막혔을 때만 외부 API 로 올린다.

두 조각으로 나뉜다. 둘은 독립이다:
  - `tier_for(phase, round_idx)` — **무엇이 어려운가**를 정한다(정책).
  - `HybridProvider`            — **어려우면 어디로 보내는가**를 정한다(배선).

단일 프로바이더(claude 만, ollama 만)에서도 `tier_for` 는 그대로 쓸모가 있다.
Claude 한 곳이라도 열거는 haiku, 권한상승은 opus 로 갈라져 비용이 준다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .llm.base import LLMProvider, LLMResponse, Tier

_ORDER = (Tier.CHEAP, Tier.STANDARD, Tier.STRONG)

# phase 별 기본 난이도. 열거/정찰은 일상(저렴·로컬), 침투·권한상승·측면이동은
# 추론 부담이 커 한 단계 위에서 시작한다.
_PHASE_BASE = {
    "recon": Tier.CHEAP,
    "enum": Tier.CHEAP,
    "access": Tier.STANDARD,
    "privesc": Tier.STANDARD,
    "lateral": Tier.STANDARD,
}


# ──────────────────────────────────────────────────────────────────
# 모델 능력 프로필 — '어떤 모델이 들어와도' 프롬프트를 그 모델에 맞춘다
# ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ModelProfile:
    klass: str      # high | mid | low
    target: int     # 프롬프트 목표 토큰(소프트). 이만큼 '채우는' 게 아니라 넘지 않는 선
    ceiling: int    # 하드 상한 — 시스템 프롬프트 포함
    items: int      # 한 번에 요청할 후보 수
    fewshot: int    # 시스템 프롬프트에 넣을 형식 예시 수(약할수록 많이)
    max_out: int    # 응답 max_tokens (Claude 는 사고 토큰 포함 — 넉넉히)
    scale: float    # 섹션별 항목 수 스케일 (target / 4000)


# (target, ceiling, items, fewshot, max_out) — 1M 창에서도 '필요한 만큼만' 넣는다:
# 비용은 입력 토큰에 선형이고, 긴 컨텍스트는 정확도도 떨어뜨린다. 한 번의 후보 생성에
# 필요한 신호(상태 요약·KB 상위·최근 관측·죽은 가설)는 3~4k 토큰이면 충분하다.
_CLASSES = {
    "high": (4000, 8000, 5, 0, 8000),
    "mid":  (3000, 6000, 4, 2, 8000),
    "low":  (2000, 4000, 3, 3, 1536),
}
_REASONING = re.compile(r"deepseek-r1|qwq|qwen3|gpt-oss|magistral|think|reason", re.I)
_MOE = re.compile(r"(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)b", re.I)
_PARAMS = re.compile(r"(\d+(?:\.\d+)?)b\b", re.I)


def _param_billions(name: str) -> float:
    m = _MOE.search(name)
    if m:
        return float(m.group(1)) * float(m.group(2))
    m = _PARAMS.search(name)
    return float(m.group(1)) if m else 0.0


def profile_for(model: str, num_ctx: int | None = None) -> ModelProfile:
    """모델명 → 능력 등급 → 프롬프트 예산. 알 수 없으면 보수적으로 low.

    '소넷급 로컬'은 파라미터 수(≥30B)로 mid 로 잡는다. 로컬은 창(num_ctx)이 작아
    목표를 창의 35%, 상한을 60% 로 묶고 나머지를 출력·여유로 남긴다.
    """
    m = (model or "").lower()
    local = not m.startswith("claude")
    if not local:
        if re.search(r"opus|fable|mythos", m):
            klass = "high"
        elif "haiku" in m:
            klass = "low"
        else:
            klass = "mid"            # sonnet 및 알 수 없는 claude-*
    else:
        klass = "mid" if _param_billions(m) >= 30 else "low"
    target, ceiling, items, fewshot, max_out = _CLASSES[klass]
    if local:
        if _REASONING.search(m):
            max_out = max(max_out, 4096)     # 사고형은 <think> 로 출력이 길다
        if num_ctx:
            ceiling = min(ceiling, int(num_ctx * 0.6))
            target = min(target, int(num_ctx * 0.35))
            max_out = min(max_out, max(256, num_ctx - ceiling))
    return ModelProfile(klass, target, ceiling, items, fewshot, max_out, target / 4000)


def _rank(t: Tier) -> int:
    return _ORDER.index(t)


def tier_for(phase: str, round_idx: int = 0, floor: Tier = Tier.CHEAP) -> Tier:
    """(단계, 막힌 정도) → 티어.

    같은 단계를 라운드가 거듭될수록(= 저렴한 모델이 못 풀고 있을수록) 한 단계씩
    올린다. 이게 '난이도별' 의 난이도 신호다 — 안 풀리면 더 센 모델.
    `floor` 는 하한(사용자가 `--llm-tier strong` 으로 전부 강제하는 경우).
    """
    base = _PHASE_BASE.get(phase, Tier.STANDARD)
    level = max(_rank(base), _rank(floor)) + max(round_idx, 0)
    return _ORDER[min(level, len(_ORDER) - 1)]


class HybridProvider(LLMProvider):
    """로컬 기본 + 어려운 호출만 외부 API 로 승격 — 토큰 절감의 실제 배선.

    `external_from` 이상의 티어는 외부로, 그 미만은 로컬로 보낸다. 선택된 쪽이
    실패하면(네트워크·미설치 등) 나머지 한쪽으로 폴백한다 — 한쪽이 None 이어도
    동작한다. 반환되는 `LLMResponse.model` 은 실제 응답한 프로바이더의 모델명이라
    비용 집계가 자동으로 맞는다.
    """

    name = "hybrid"

    def __init__(self, local: LLMProvider | None, external: LLMProvider | None,
                 external_from: Tier = Tier.STRONG):
        if local is None and external is None:
            raise ValueError("hybrid: local·external 둘 다 None")
        self.local = local
        self.external = external
        self.external_from = external_from

    @property
    def models(self) -> dict:  # type: ignore[override]
        # 참고용 병합(표시 전용). '이 티어를 누가 처리하나'는 model_for 가 답한다.
        merged: dict = {}
        for p in (self.local, self.external):
            if p:
                merged.update(p.models)
        return merged

    def model_for(self, tier: Tier) -> str:
        # 병합 dict 는 외부가 로컬을 덮어써, CHEAP 이 로컬로 라우팅되는데도 Claude 모델명을
        # 돌려줬다 — 프롬프트 예산이 엉뚱한 모델 기준으로 잡힌다. 1순위 프로바이더가 답한다.
        return self._route(tier)[0].model_for(tier)

    def num_ctx_for(self, tier: Tier) -> int | None:
        return self._route(tier)[0].num_ctx_for(tier)

    def available(self) -> tuple[bool, str]:
        avail = []
        for label, p in (("local", self.local), ("external", self.external)):
            if p is None:
                continue
            ok, _why = p.available()
            if ok:
                avail.append(f"{label}={p.name}")
        if avail:
            return True, "hybrid(" + ", ".join(avail) + ")"
        return False, "hybrid: 로컬·외부 모두 사용 불가"

    def _route(self, tier: Tier) -> list[LLMProvider]:
        """티어 → 시도 순서(1순위 먼저). None 은 제외."""
        if _rank(tier) >= _rank(self.external_from):
            order = (self.external, self.local)      # 어려움 → 외부 우선
        else:
            order = (self.local, self.external)      # 일상 → 로컬 우선
        return [p for p in order if p is not None]

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        providers = self._route(tier)
        last_err: Exception | None = None
        for p in providers:
            try:
                return p.complete(system, user, tier, max_tokens)
            except Exception as e:                   # 선택된 쪽 실패 → 폴백
                last_err = e
        raise RuntimeError(f"hybrid: 모든 프로바이더 실패 — {last_err}")
