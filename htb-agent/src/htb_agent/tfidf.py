"""
경량 TF-IDF 코사인 랭킹 — 표준 라이브러리만(임베딩/외부 의존 없음)
====================================================================

`knowledge.relevant_notes` 의 '키워드 겹침 개수' 랭킹을 TF-IDF 코사인으로 보강한다. 희귀
용어에 가중치를 주고(흔한 단어의 지배 방지) 문서 길이로 정규화해, 긴 노트가 단순히 토큰이
많다는 이유로 상위를 독식하지 않게 한다. 벡터 임베딩(ada 류)이 아니라 **어휘 기반**이므로
오프라인·무과금·결정적이다(라인레벨 감사의 '임베딩 부재' 지적에 대한 stdlib 범위 보강).
"""
from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9]{2,}")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall((text or "").lower())


class TfidfIndex:
    """작은 코퍼스(KB 노트 등)용 TF-IDF 색인. 생성 시 df/idf 계산, rank 로 질의."""

    def __init__(self, docs: list[str]):
        self.docs = docs
        self._tf: list[Counter] = [Counter(tokenize(d)) for d in docs]
        n = len(docs)
        df: Counter = Counter()
        for tf in self._tf:
            for term in tf:
                df[term] += 1
        # smoothed idf — 전 문서 등장 용어도 0 이 되지 않게(+1), 희귀 용어 가중.
        self._idf: dict[str, float] = {
            t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}
        self._norm: list[float] = [self._vec_norm(tf) for tf in self._tf]

    def _vec_norm(self, tf: Counter) -> float:
        return math.sqrt(sum((f * self._idf.get(t, 0.0)) ** 2 for t, f in tf.items()))

    def rank(self, terms: list[str], limit: int = 3) -> list[tuple[int, float]]:
        """질의 용어에 대한 (문서 index, 코사인 점수) 내림차순 — 점수>0 만, 상위 limit.
        동점은 원래 순서(index 오름차순) 유지(결정적)."""
        q = Counter(t.lower() for t in terms if t and len(t) >= 2)
        if not q or not self.docs:
            return []
        qw = {t: f * self._idf.get(t, 0.0) for t, f in q.items()}
        qnorm = math.sqrt(sum(w * w for w in qw.values()))
        if qnorm == 0:
            return []
        out: list[tuple[int, float]] = []
        for i, tf in enumerate(self._tf):
            dn = self._norm[i]
            if dn == 0:
                continue
            dot = sum(qw.get(t, 0.0) * f * self._idf.get(t, 0.0) for t, f in tf.items())
            if dot > 0:
                out.append((i, dot / (qnorm * dn)))
        out.sort(key=lambda x: (-x[1], x[0]))
        return out[:limit]
