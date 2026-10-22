"""
tiering — 난이도별 모델 차등 선택(선별 이식)
============================================

(출처: 해커톤 포크 `pokochy/htb-autonomous-agent-lab` 의 `tiering.py` 에서 **선별** 이식.
HybridProvider 는 루트 `llm/router.py` 의 `HybridRouter`(서킷브레이커·쿨다운·통계)가 더
정교하므로 가져오지 않는다. 라운드 기반 티어 상승(`tier_for`)과 모델별 프롬프트 예산
(`profile_for`/`ModelProfile`)만 가져온다.)

  - `tier_for(phase, round_idx)` — **무엇이 어려운가**(정책). 같은 단계가 라운드를 거듭할수록
    (= 저렴한 모델이 못 풀고 있을수록) 한 단계씩 올린다. **phase 기본값은 루트의
    `tier_for_phase` 를 그대로 쓴다**(privesc/lateral 은 처음부터 STRONG — 회귀 방지).
  - `profile_for(model)` — 모델명 → 능력 등급 → 프롬프트 토큰 예산(`ModelProfile`). `context.py`
    의 `ContextBuilder.build(target, ceiling)` 에 바로 넣을 수 있는 숫자다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Tier, tier_for_phase

_ORDER = (Tier.CHEAP, Tier.STANDARD, Tier.STRONG)


def _rank(t: Tier) -> int:
    return _ORDER.index(t)


def tier_for(phase: str, round_idx: int = 0, floor: Tier = Tier.CHEAP) -> Tier:
    """(단계, 막힌 정도) → 티어. 같은 단계를 라운드가 거듭될수록 한 단계씩 올린다
    (안 풀리면 더 센 모델). phase 기본 난이도는 루트 `tier_for_phase` 를 따른다
    (enum=CHEAP·access=STANDARD·privesc/lateral=STRONG). `floor` 는 하한(`--llm-tier` 강제)."""
    base = tier_for_phase(phase)
    level = max(_rank(base), _rank(floor)) + max(round_idx, 0)
    return _ORDER[min(level, len(_ORDER) - 1)]


# ── 모델 능력 프로필 — '어떤 모델이 들어와도' 프롬프트를 그 모델에 맞춘다 ──────────
@dataclass(frozen=True)
class ModelProfile:
    klass: str      # high | mid | low
    target: int     # 프롬프트 목표 토큰(소프트). 이만큼 '채우는' 게 아니라 넘지 않는 선
    ceiling: int    # 하드 상한 — 시스템 프롬프트 포함
    items: int      # 한 번에 요청할 후보 수
    fewshot: int    # 시스템 프롬프트에 넣을 형식 예시 수(약할수록 많이)
    max_out: int    # 응답 max_tokens
    scale: float    # 섹션별 항목 수 스케일(target / 4000)


# (target, ceiling, items, fewshot, max_out) — 1M 창에서도 '필요한 만큼만': 비용은 입력 토큰에
# 선형이고 긴 컨텍스트는 정확도도 떨어뜨린다. 한 번의 후보 생성에 필요한 신호는 3~4k 토큰이면 충분.
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

    'opus/fable'급은 high, 'haiku'는 low, 그 외 claude-* 는 mid. 로컬('claude' 로 시작 안 함)은
    파라미터 수(≥30B)로 mid, 아니면 low. 로컬은 창(num_ctx)이 작아 목표를 창의 35%·상한을
    60% 로 묶고 나머지를 출력·여유로 남긴다."""
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
