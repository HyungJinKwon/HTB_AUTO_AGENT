"""
Next-Step Recommender — 다음 선택지 제안 (휴먼인더루프, 사람이 선택·승인)
==========================================================================

막힌 지점(진단)·정체(반복)·대기 단계를 근거와 함께 **선택지로 정리**해 사람에게
제시한다. 에이전트가 다음 공격을 자동으로 고르거나 실행하지 않는다 — **무엇을 할지
사람이 고르고 승인**하면, 그때 비로소 기존 3관문(검증→범위→승인)을 거쳐 실행된다.

원칙:
  · 새로운 공격 기법을 생성하지 않는다. 이미 산출된 진단 힌트·KB 수동 제안·단계 상태를
    모아 '정리·우선순위화'만 한다.
  · 각 선택지는 근거(왜 이것인가)를 달아, 사람이 판단하도록 한다.
  · 이 모듈은 상태를 바꾸지 않고 네트워크도 쓰지 않는다(권고 텍스트만 생성).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import repetition as _rep


@dataclass
class Recommendation:
    title: str                 # 선택지 제목(사람이 고를 항목)
    rationale: str             # 근거(왜 이 선택지인가)
    source: str = ""           # diagnosis / phase / repetition / kb
    ref: str = ""              # 관련 명령/경로(있으면 — 참고용)
    priority: int = 5          # 낮을수록 먼저 보여줌


@dataclass
class RecommendationSet:
    items: list[Recommendation] = field(default_factory=list)

    @property
    def has_items(self) -> bool:
        return bool(self.items)


# 단계 키 → 한국어 라벨(리포트와 일관)
_PHASE_LABEL = {
    "enum": "열거", "access": "초기 침투", "privesc": "권한 상승",
    "lateral": "측면 이동",
}


def propose(report, *, max_items: int = 8, repetition=None) -> RecommendationSet:
    """리포트의 진단·정체·단계 상태에서 '사람이 고를 다음 선택지'를 만든다.
    자동 실행하지 않는다 — 선택·승인은 사람이 한다."""
    recs: list[Recommendation] = []

    # 1) 대상 응답(진단) — 각 범주의 힌트를 선택지로(중복 범주 1회)
    seen_cat: set[str] = set()
    for cmd, d in getattr(report, "blockers", []) or []:
        if getattr(d, "is_target", False) and getattr(d, "hint", "") and d.category not in seen_cat:
            seen_cat.add(d.category)
            recs.append(Recommendation(
                title=f"{d.label} 대응 각도 검토",
                rationale=d.hint, source="diagnosis", ref=cmd, priority=2))

    # 2) 환경/네트워크 문제 — 하나로 묶어 '먼저 확인' 제안(경로 실패 아님)
    env_cats = sorted({d.category for _c, d in (getattr(report, "blockers", []) or [])
                       if not getattr(d, "is_target", False)})
    if env_cats:
        recs.append(Recommendation(
            title="환경/네트워크 먼저 확인(경로 실패 아님)",
            rationale="환경 문제(" + ", ".join(env_cats) + ")로 일부 시도가 막힘 — "
                      "도달성·도구·속도를 사람이 먼저 점검하면 유효 경로를 섣불리 버리지 않음",
            source="diagnosis", priority=1))

    # 3) 반복·정체 — 각도 전환을 '사람이' 검토하도록 제안
    # 호출측이 이미 계산했다면 재사용(리포트 렌더 시 중복 분석 방지)
    rr = repetition if repetition is not None else _rep.analyze(
        getattr(report, "enum_findings", []) + getattr(report, "llm_findings", []),
        getattr(report, "blockers", []))
    if rr.stalled or rr.repeated_failures or rr.repeated_cmds:
        why = []
        if rr.repeated_cmds:
            why.append("같은 종류 명령 반복")
        if rr.repeated_failures:
            why.append("같은 실패 반복")
        if rr.stalled:
            why.append("정체(유의미한 출력 희박)")
        recs.append(Recommendation(
            title="접근 각도 전환 검토",
            rationale=" / ".join(why) + " — 한 경로에 매달리는 중일 수 있어 다른 서비스·도구·"
                      "경로를 사람이 선택", source="repetition", priority=3))

    # 3.5) [T2-d] 궤적 드리프트 supervisor — 명령 레벨 반복(3)과 별개로, '가설 레벨'에서
    # 막힌 가설이 쌓이고 쫓을 신선한 가설이 없으면(래빗홀) 전면 재검토를 권고(결정적·advisory).
    plan = getattr(report, "plan", None)
    if plan is not None and getattr(plan, "items", None):
        stuck_h = plan.stuck()
        foc = plan.focus()
        if len(stuck_h) >= 2 and (foc is None or getattr(foc, "status", "") == "confirmed"):
            recs.append(Recommendation(
                title="가설 전면 재검토(궤적 드리프트)",
                rationale=f"막힌 가설 {len(stuck_h)}개 + 쫓을 신선한 가설 없음 — 한 궤적에 갇혔을 "
                          "수 있어 관측을 원점에서 다시 보고 새 가설을 세우길 권장",
                source="supervisor", priority=2))

    # 4) 대기 단계(전제 미충족) — 전제 확보 안내
    for key, status in (getattr(report, "phase_status", {}) or {}).items():
        if isinstance(status, str) and status.startswith("대기"):
            label = _PHASE_LABEL.get(key, key)
            recs.append(Recommendation(
                title=f"'{label}' 단계 전제 확보 후 재개",
                rationale=f"{status} — 전제(자격·권한 등) 확보 시 이 단계가 유효해짐",
                source="phase", priority=4))

    # 5) 대기 중 KB 수동 제안 — 같은 문구를 여러 번 늘어놓지 않고 '종류별 한 줄'로 묶는다
    manual = list(getattr(report, "manual_suggestions", []) or [])
    over = [s for s in manual if "상한 초과" in s]
    cred = [s for s in manual if any(p in s for p in ("{user}", "{pass}", "{domain}", "{hash}"))]
    other = [s for s in manual if s not in over and s not in cred
             and "(수동)" not in s and "실행위험" not in s]
    if over:
        recs.append(Recommendation(
            title=f"못 돌린 명령 {len(over)}개 이어서 실행",
            rationale="실행 상한(--max-enum)을 넘어 대기 중 — 같은 명령에 --resume 을 붙이면 이미 한 "
                      "명령은 건너뛰고 이어서 실행(또는 --max-enum 을 늘려 재실행)",
            source="kb", ref=over[0].split("   #")[0], priority=4))
    if cred:
        recs.append(Recommendation(
            title=f"자격증명이 필요한 명령 {len(cred)}개",
            rationale="찾은 계정이 있으면 --cred 사용자:비밀번호 를 붙여 재실행 — 자리표시자를 자동으로 채움",
            source="kb", ref=cred[0].split("   #")[0], priority=4))
    if other:
        recs.append(Recommendation(
            title=f"참고 명령 {len(other)}개 검토",
            rationale="단계·플랫폼별 참고 명령 — 필요한 것을 골라 승인/입력 후 실행",
            source="kb", ref=other[0], priority=6))

    # 중복 title+ref 제거, 우선순위 정렬, 상한
    uniq: list[Recommendation] = []
    seen_key: set[tuple] = set()
    for r in sorted(recs, key=lambda x: x.priority):
        k = (r.title, r.ref)
        if k in seen_key:
            continue
        seen_key.add(k)
        uniq.append(r)
    return RecommendationSet(items=uniq[:max_items])
