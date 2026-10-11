"""LLM-심판 게이트 (A6, opt-in · advisory) — ARTEX 'LLM-judge' 아이디어의 정직성-보존 이식.

'풀었다'(플래그/발판 확보) 주장이 **증거로 실제 뒷받침되는가**를 별도 LLM 호출로 루브릭 채점해
사람에게 조언으로 제시한다. **규칙 기반 판정(provenance·verify·goal_reached)을 절대 덮지 않는다**
— 어디까지나 보조 의견이다. `--judge` + LLM 라우터가 있을 때만 돌고(기본 비활성·비용 0),
결과는 report.judge_verdict 에 실려 리포트에만 표시된다.

정직성 경계: 심판이 'pass' 해도 미신뢰 플래그가 goal 로 승격되지 않고, 'fail' 해도 공략 유래
플래그가 격하되지 않는다. 심판은 '추가 회의(skeptic) 한 겹'일 뿐이다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

JUDGE_SYSTEM = (
    "당신은 모의해킹 결과의 '적대적 심판(judge)'이다. 주어진 증거(획득 플래그·그 출처 판정·실행한 "
    "명령 요약·권한 상태)만 보고, '목표를 실제로 공략으로 달성했다'는 주장이 증거로 뒷받침되는지 "
    "회의적으로 채점하라. 라이트업 암기·로컬 미끼 문자열·추측으로 보이는 플래그는 낮게 매긴다. "
    "오직 JSON 한 줄로만 답하라: {\"score\": 0-100, \"passed\": true|false, \"rationale\": \"한 문장\"}. "
    "score 는 '증거가 실제 공략 달성을 뒷받침하는 정도', passed 는 score>=70 권장. 그 외 설명 금지."
)


@dataclass
class JudgeVerdict:
    score: int           # 0-100 — 증거가 공략 달성을 뒷받침하는 정도
    passed: bool         # 조언: 증거가 충분한가(규칙 판정을 덮지 않음)
    rationale: str = ""

    def label(self) -> str:
        return ("🧪 심판(조언): "
                + (f"뒷받침됨({self.score})" if self.passed else f"근거 불충분({self.score})")
                + (f" — {self.rationale}" if self.rationale else ""))


def build_judge_user(context: dict, target: str) -> str:
    """심판용 사용자 프롬프트 — 증거 요약(플래그·출처 판정·상태). context 는 orchestrator 가 구성."""
    lines = [f"타겟: {target}"]
    flags = context.get("flags") or []
    if flags:
        lines.append("획득 플래그와 출처 판정:")
        for f in flags:
            lines.append(f"  - {f}")
    else:
        lines.append("획득 플래그: 없음")
    if context.get("access_level"):
        lines.append(f"권한 상태: {context['access_level']}")
    if context.get("state"):
        lines.append("상태 요약:\n  " + "\n  ".join(context["state"][:8]))
    if context.get("commands"):
        lines.append("대표 실행 명령(최근):\n  " + "\n  ".join(context["commands"][:8]))
    lines.append("위 증거만으로 '공략으로 목표 달성'이 뒷받침되는지 JSON 으로 채점하라.")
    return "\n".join(lines)


_JSON_RE = re.compile(r"\{.*\}", re.S)


def parse_judge(text: str) -> JudgeVerdict | None:
    """심판 응답(JSON 한 줄)을 파싱. 실패하면 None(조언 생략 — 규칙 판정엔 영향 없음)."""
    if not text:
        return None
    m = _JSON_RE.search(text)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    try:
        score = int(d.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))
    passed = bool(d.get("passed", score >= 70))
    rationale = str(d.get("rationale", ""))[:300]
    return JudgeVerdict(score=score, passed=passed, rationale=rationale)
