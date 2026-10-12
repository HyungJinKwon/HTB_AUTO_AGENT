"""
Hypotheses — 가설 기록(계획 원장): LLM 이 '처음부터 다시' 가 아니라 '방향을 이어서' 진행하게
==========================================================================================

하이브리드 모드의 역할 분담:
  · 분석가(강력 모델, Claude)  = 전략가. 가설 기록을 만들고 '의미 있는 변화' 때만 갱신한다.
  · 명령 생성(로컬 모델 우선) = 실행자. 기록에서 고른 '지금 할 일 1개'에 집중해 명령을 낸다.
  · 결과 ↔ 기대 신호 대조     = 규칙 기반(LLM 없음). 가설 상태를 갱신하고, 같은 가설이
                                연속으로 막히면(기본 2회) 재계획 신호를 낸다.

가설 상태는 **명령 제안의 방향**에만 쓰인다. 실행은 여전히 검증→범위→승인 3관문을 거치고,
플래그 출처·목표 달성 판정은 실행 트레이스로만 한다(가설이 '확인'이어도 판정에 쓰지 않음).
LLM 이 준 가설 문구·기대 신호는 신뢰할 수 없는 데이터라 길이를 자르고 그대로 표시만 한다.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

# 상태 키 → (표시 라벨, 기호)
STATUS = {
    "pending": ("대기", "·"),
    "testing": ("검증중", "…"),
    "confirmed": ("확인", "✔"),
    "rejected": ("기각", "✗"),
}
_STATUS_ALIASES = {
    "pending": "pending", "대기": "pending", "open": "pending", "new": "pending",
    "testing": "testing", "검증중": "testing", "검증": "testing", "in_progress": "testing",
    "confirmed": "confirmed", "확인": "confirmed", "confirm": "confirmed", "verified": "confirmed",
    "rejected": "rejected", "기각": "rejected", "reject": "rejected", "refuted": "rejected",
}
_PRIORITY_ORDER = {"상": 0, "중": 1, "하": 2}
_PRIORITY_ALIASES = {"상": "상", "high": "상", "중": "중", "medium": "중", "mid": "중",
                     "하": "하", "low": "하"}
# [T1-b] 기대값(EV) 점수화 — redcat2 교리의 confidence×impact÷cost 를 승인제 구조에 맞춰
# 결정적(규칙 기반)으로 이식. priority=신뢰도/중요도 대용, impact=진전 기여, cost=노력/리스크.
# 가중치는 상/중/하 3단계(전부 '중'이면 EV==priority 서수라 하위호환 — 기존 동작 불변).
_WEIGHT = {"상": 3, "중": 2, "하": 1}          # 클수록 좋음(신뢰도·영향)
_COST_WEIGHT = {"상": 3, "중": 2, "하": 1}      # 클수록 비쌈(분모)

MAX_ACTIVE = 6        # 동시에 들고 가는 가설 상한(대기·검증중·확인)
_TEXT_MAX = 160
_FIELD_MAX = 120
_ID_RE = re.compile(r"\bH(\d{1,2})\b", re.I)


def _clip(s, n: int = _FIELD_MAX) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _norm_status(s) -> str:
    return _STATUS_ALIASES.get(str(s or "").strip().lower(), "")


def _norm_priority(s) -> str:
    return _PRIORITY_ALIASES.get(str(s or "").strip().lower(), "")


def parse_id(s) -> str:
    """'H1', 'h1: ...', '가설 H2' 등에서 'H1' 형태 ID 추출(없으면 '')."""
    m = _ID_RE.search(str(s or ""))
    return f"H{int(m.group(1))}" if m else ""


@dataclass
class Hypothesis:
    id: str
    text: str
    priority: str = "중"
    status: str = "pending"
    check: str = ""        # 가장 싼 확인 방법
    expected: str = ""     # 기대 신호(확인되면 출력에 보일 것)
    fallback: str = ""     # 기각 시 넘어갈 대안
    impact: str = "중"     # [T1-b] 진전 기여(상/중/하) — 맞으면 공략이 얼마나 전진하나
    cost: str = "중"       # [T1-b] 노력·리스크(상/중/하) — 확인에 드는 비용(분모)
    depends_on: list[str] = field(default_factory=list)  # [T2-a] 전제 가설 ID(이게 기각되면 보류)
    tried: list[str] = field(default_factory=list)      # 이 가설로 시도한 명령
    evidence: list[str] = field(default_factory=list)   # "명령 → 신호 일치/불일치" 한 줄씩
    hits: int = 0
    misses: int = 0        # 연속 불일치(일치하면 0으로)

    @property
    def label(self) -> str:
        return STATUS.get(self.status, ("?", "?"))[0]

    @property
    def mark(self) -> str:
        return STATUS.get(self.status, ("?", "?"))[1]

    @property
    def ev(self) -> float:
        """기대값 점수 = (신뢰도 × 영향 ÷ 비용) × 최근결과 보정. 클수록 먼저 쫓는다.
        전부 '중'이면 base=priority 가중치와 비례해 하위호환(기존 우선순위 정렬과 동일 순서).
        연속 불일치(misses)가 쌓일수록 감쇠 — 완전히 막히기 전에 신선한 각도를 먼저 쓰게."""
        conf = _WEIGHT.get(self.priority, 2)
        imp = _WEIGHT.get(self.impact, 2)
        cost = _COST_WEIGHT.get(self.cost, 2)
        base = conf * imp / cost
        return base / (1 + 0.5 * max(0, self.misses))


# ── 기대 신호 대조(규칙 기반, 보수적) ─────────────────────────────────
_STOP = {
    "with", "from", "that", "this", "will", "should", "show", "shows", "page", "response",
    "output", "result", "results", "found", "contains", "contain", "exists", "exist", "있음",
    "확인", "응답", "결과", "출력", "포함", "여부", "가능", "표시", "the", "and", "for",
}
_NEGATIVE = ("denied", "failed", "failure", "refused", "invalid", "incorrect", "forbidden",
             "unauthorized", "not found", "not allowed", "disabled", "거부", "실패", "없음")


def signal_terms(expected: str) -> tuple[list[str], list[str]]:
    """기대 신호에서 (강한 단서, 약한 단서) 추출.
    강한 단서: 따옴표 문자열 · 경로(/x) · HTTP 상태코드 · 포트/숫자-단어 조합
    약한 단서: 4자 이상 영문 단어(불용어 제외)."""
    exp = str(expected or "")
    strong: list[str] = []
    for q in re.findall(r"[\"'`“‘]([^\"'`”’]{2,60})[\"'`”’]", exp):
        strong.append(q.strip())
    strong += re.findall(r"(?<![\w.])/[A-Za-z0-9._\-/]{2,60}", exp)
    strong += re.findall(r"\b[1-5]\d\d\b", exp)
    weak = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}", exp)
            if w.lower() not in _STOP]
    return _dedup(strong), [w for w in _dedup(weak) if w.lower() not in {s.lower() for s in strong}]


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it and it.lower() not in seen:
            seen.add(it.lower())
            out.append(it)
    return out


def match_signal(expected: str, output: str) -> bool | None:
    """기대 신호가 출력에 보이면 True, 보이지 않으면 False, 판단 재료가 없으면 None.
    강한 단서 하나라도 보이면 일치. 강한 단서가 없으면 약한 단서 2개 이상(또는 1개뿐이면 그 1개)."""
    strong, weak = signal_terms(expected)
    if not strong and not weak:
        return None
    low = (output or "").lower()
    if any(s.lower() in low for s in strong):
        return True
    if strong and not weak:
        return False
    hit = sum(1 for w in weak if w.lower() in low)
    need = 1 if len(weak) == 1 else 2
    if hit < need:
        return False
    # 약한 단서만으로 맞췄는데 출력이 거부·실패를 말하면(기대 신호엔 없는 부정어) 일치로 보지 않음
    # 예: 기대 "anonymous login allowed" vs 출력 "Anonymous login denied"
    exp_low = str(expected or "").lower()
    return not any(n in low and n not in exp_low for n in _NEGATIVE)


@dataclass
class HypothesisLedger:
    items: list[Hypothesis] = field(default_factory=list)
    revision: int = 0          # 분석가 갱신 횟수
    replan_after: int = 2      # 같은 가설 연속 불일치 N회 → 막힘(재계획 신호)

    # ── 조회 ──
    def get(self, hid: str) -> Hypothesis | None:
        hid = parse_id(hid)
        return next((h for h in self.items if h.id == hid), None)

    def __bool__(self) -> bool:
        return bool(self.items)

    def budget(self, h: Hypothesis) -> int:
        """[T1-b] 가설별 가변 증거예산(막힘 판정 임계). 영향 큰·비용 낮은 가설엔 더 많은 시도를,
        영향 작은·비용 높은 가설엔 더 적은 시도를 준다. 전부 '중'이면 replan_after 와 같아
        하위호환(기존 고정 임계와 동일). 최소 1."""
        imp = _WEIGHT.get(h.impact, 2)
        cost = _COST_WEIGHT.get(h.cost, 2)
        return max(1, round(self.replan_after * imp / cost))

    def dep_blocked(self, h: Hypothesis) -> bool:
        """[T2-a] 전제(depends_on) 가설이 '기각'됐으면 이 가설은 보류(하류 가지치기).
        MazeRunner 의 blocked 하류 prune 을 '전제 기각' 한 축으로 결정적 구현(전면 DAG 는
        ADR A3/A4 로 미채택 — 순효과 마이너스). 자기참조·미존재 ID 는 무시."""
        if not h.depends_on:
            return False
        rejected = {x.id for x in self.items if x.status == "rejected"}
        return any(parse_id(d) in rejected and parse_id(d) != h.id for d in h.depends_on)

    def stuck(self) -> list[Hypothesis]:
        return [h for h in self.items
                if h.status in ("pending", "testing") and h.misses >= self.budget(h)]

    def focus(self) -> Hypothesis | None:
        """'지금 할 일' 1개: 막히지 않은 대기·검증중 가설을 기대값(EV) 높은 순으로, 없으면 확인된
        가설(심화 — 다음 단계로 이어가기), 그것도 없으면 None. 기각·막힘 가설은 고르지 않는다.
        EV 동률이면 ID 오름차순(결정적). 전부 '중'·misses=0 이면 priority 정렬과 동일 순서."""
        def key(h: Hypothesis):
            return (-h.ev, int(h.id[1:]) if h.id[1:].isdigit() else 99)
        stuck = {h.id for h in self.stuck()}
        open_ = [h for h in self.items if h.status in ("testing", "pending")
                 and h.id not in stuck and not self.dep_blocked(h)]
        if open_:
            return sorted(open_, key=key)[0]
        conf = [h for h in self.items if h.status == "confirmed"]
        return sorted(conf, key=key)[0] if conf else None

    def signature(self) -> tuple:
        """재계획 판정용 — 가설별 (ID, 결론, 막힘 여부). 대기→검증중은 결론이 아니라 같은 값
        ('open')으로 본다. 확인·기각되거나 새로 막히면 달라진다."""
        stuck = {h.id for h in self.stuck()}
        coarse = {"pending": "open", "testing": "open"}
        return tuple((h.id, coarse.get(h.status, h.status), h.id in stuck) for h in self.items)

    # ── 분석가 갱신 ──
    def apply_update(self, data) -> int:
        """분석가가 준 가설 목록을 병합(처음부터 다시 쓰지 않음). 반환: 반영한 가설 수.
          · 기존 ID 는 문구·우선순위·상태·확인 방법만 갱신하고 시도·근거·횟수는 유지
          · 확인 방법/기대 신호를 바꿨거나 상태를 다시 열면 연속 불일치를 0으로(새 시도 기회)
          · 언급하지 않은 기존 가설은 그대로 둔다(삭제 없음)
          · 새 ID 는 추가하되 활성 가설은 MAX_ACTIVE 개까지만"""
        if isinstance(data, dict):
            data = data.get("hypotheses") or data.get("items") or []
        if not isinstance(data, list):
            return 0
        applied = 0
        for it in data:
            if not isinstance(it, dict):
                continue
            hid = parse_id(it.get("id") or it.get("hypothesis") or "")
            text = _clip(it.get("text") or it.get("hypothesis_text") or it.get("desc") or "",
                         _TEXT_MAX)
            if not hid:
                continue
            status = _norm_status(it.get("status"))
            prio = _norm_priority(it.get("priority"))
            impact = _norm_priority(it.get("impact"))   # 상/중/하 (priority 와 동일 어휘)
            cost = _norm_priority(it.get("cost"))
            check = _clip(it.get("check") or "")
            expected = _clip(it.get("expected") or it.get("expected_signal") or "")
            fallback = _clip(it.get("fallback") or "")
            deps = [parse_id(d) for d in (it.get("depends_on") or it.get("deps") or [])
                    if parse_id(d) and parse_id(d) != hid][:4]
            h = self.get(hid)
            if h is None:
                if not text:
                    continue
                active = [x for x in self.items if x.status != "rejected"]
                if len(active) >= MAX_ACTIVE and status != "rejected":
                    continue
                self.items.append(Hypothesis(id=hid, text=text, priority=prio or "중",
                                             status=status or "pending", check=check,
                                             expected=expected, fallback=fallback,
                                             impact=impact or "중", cost=cost or "중",
                                             depends_on=deps))
                applied += 1
                continue
            reopened = False
            if text:
                h.text = text
            if prio:
                h.priority = prio
            if impact:
                h.impact = impact
            if cost:
                h.cost = cost
            if deps:
                h.depends_on = deps
            if check and check != h.check:
                h.check, reopened = check, True
            if expected and expected != h.expected:
                h.expected, reopened = expected, True
            if fallback:
                h.fallback = fallback
            if status and status != h.status:
                # 결론(확인·기각)을 다시 열 때만 새 기회 — 대기↔검증중 전환은 해당 없음
                reopened = reopened or (h.status in ("confirmed", "rejected")
                                        and status in ("pending", "testing"))
                h.status = status
            if reopened:
                h.misses = 0
            applied += 1
        if applied:
            self.revision += 1
        return applied

    def apply_text(self, text: str) -> int:
        """분석가 응답에서 가설을 읽어 병합. '가설기록' JSON 줄을 우선, 없으면 'H1 [우선:상] …'
        텍스트 줄을 해석(폴백). 반환: 반영한 가설 수."""
        data = extract_ledger_json(text)
        if data is not None:
            n = self.apply_update(data)
            if n:
                return n
        return self.apply_update(parse_hypothesis_lines(text))

    # ── 결과 대조 ──
    def record(self, hid: str, command: str, output: str, ran: bool,
               target_rejected: bool = False) -> str:
        """이 가설로 낸 명령의 결과를 대조해 상태를 갱신. 반환: 'hit' / 'miss' / 'neutral'.
          · 실행 안 됨(미승인·미설치·실행 실패/환경 문제) → neutral(가설 판단 근거 아님)
          · 기대 신호 일치 → hit: 확인(〔추정〕 — 규칙 대조), 연속 불일치 0
          · 대상이 거부(404/403…)·출력 없음·기대 신호 불일치 → miss: 연속 불일치 +1
          · 기대 신호가 없고 출력이 있으면 neutral(판단 보류)"""
        h = self.get(hid)
        if h is None:
            return "neutral"
        if command not in h.tried:
            h.tried.append(command)
        if not ran:
            return "neutral"
        if h.status == "pending":
            h.status = "testing"
        # 대상 거부(403/404 등)라도 match_signal 을 먼저 본다 — 가설이 '그 거부 자체'를 기대한
        # 경우(expected="returns 403 Forbidden" 등)엔 일치로 인정해야 한다. 과거엔 target_rejected
        # 면 match_signal 을 건너뛰고 강제 miss → 기대한 응답을 받고도 오탐 stuck/freeze 됐다.
        sig = match_signal(h.expected, output)
        verdict: bool | None
        if not (output or "").strip():
            verdict = False               # 빈 출력 → 판단 불가가 아니라 miss(실행은 됐으나 신호 無)
        elif sig is True:
            verdict = True                # 기대 신호가 실제로 보임(거부를 기대했어도 일치)
        elif target_rejected:
            verdict = False               # 기대 안 한 대상 거부 → miss
        else:
            verdict = sig                 # None=판단불가(neutral) · False=불일치
        if verdict is None:
            return "neutral"
        short = _clip(command, 60)
        if verdict:
            h.hits += 1
            h.misses = 0
            if h.status in ("pending", "testing"):
                h.status = "confirmed"
            h.evidence.append(f"{short} → 신호 일치〔추정〕")
            res = "hit"
        else:
            h.misses += 1
            h.evidence.append(f"{short} → 불일치" + ("(대상 거부)" if target_rejected else ""))
            res = "miss"
        h.evidence = h.evidence[-4:]
        return res

    # ── 표시·LLM 맥락 ──
    def board_lines(self) -> list[str]:
        """사람용 가설 보드(평문). 예: '✔ H1 [상] 확인 — 익명 FTP … (시도 2 · 일치 1)'"""
        stuck = {h.id for h in self.stuck()}
        out = []
        for h in self.items:
            extra = f"시도 {len(h.tried)}"
            if h.hits:
                extra += f" · 일치 {h.hits}"
            if h.id in stuck:
                extra += f" · 막힘(연속 불일치 {h.misses})"
            out.append(f"{h.mark} {h.id} [{h.priority}] {h.label} — {h.text} ({extra})")
        return out

    def context_lines(self) -> list[str]:
        """분석가에게 넘기는 이전 기록 — 갱신 모드의 근거(상태·확인 방법·최근 근거)."""
        stuck = {h.id for h in self.stuck()}
        out = []
        for h in self.items:
            ln = (f"{h.id} [{h.priority}·영향{h.impact}·비용{h.cost}] {h.label}"
                  f"{' · 막힘' if h.id in stuck else ''}: {h.text}")
            if h.check:
                ln += f" | 확인: {h.check}"
            if h.expected:
                ln += f" | 기대 신호: {h.expected}"
            if h.evidence:
                ln += " | 근거: " + "; ".join(h.evidence[-2:])
            out.append(ln)
        return out

    def focus_lines(self, h: Hypothesis) -> list[str]:
        """실행자(명령 생성)에게 주는 '지금 할 일' — 좁고 구체적으로."""
        lines = [f"지금 할 일: {h.id} [{h.priority}] {h.text}"]
        if h.check:
            lines.append(f"확인 방법: {h.check}")
        if h.expected:
            lines.append(f"기대 신호: {h.expected}")
        if h.tried:
            lines.append("이미 시도(반복 금지): " + "; ".join(_clip(c, 80) for c in h.tried[-4:]))
        if h.evidence:
            lines.append("최근 결과: " + "; ".join(h.evidence[-2:]))
        others = [f"{x.id} {x.label}" for x in self.items if x.id != h.id]
        if others:
            lines.append("다른 가설(참고만): " + ", ".join(others))
        return lines

    # ── 저장 ──
    def to_dict(self) -> dict:
        return {"revision": self.revision, "replan_after": self.replan_after,
                "items": [asdict(h) for h in self.items]}

    @classmethod
    def from_dict(cls, d) -> "HypothesisLedger":
        led = cls()
        if not isinstance(d, dict):
            return led
        led.revision = int(d.get("revision") or 0)
        led.replan_after = max(1, int(d.get("replan_after") or 2))
        for it in d.get("items") or []:
            if not isinstance(it, dict) or not parse_id(it.get("id")):
                continue
            led.items.append(Hypothesis(
                id=parse_id(it.get("id")), text=_clip(it.get("text"), _TEXT_MAX),
                priority=_norm_priority(it.get("priority")) or "중",
                status=_norm_status(it.get("status")) or "pending",
                check=_clip(it.get("check")), expected=_clip(it.get("expected")),
                fallback=_clip(it.get("fallback")),
                impact=_norm_priority(it.get("impact")) or "중",
                cost=_norm_priority(it.get("cost")) or "중",
                depends_on=[parse_id(d) for d in (it.get("depends_on") or []) if parse_id(d)][:4],
                tried=[str(c) for c in (it.get("tried") or [])][-20:],
                evidence=[str(e) for e in (it.get("evidence") or [])][-4:],
                hits=int(it.get("hits") or 0), misses=int(it.get("misses") or 0)))
        return led


# ── 분석가 응답 파싱 ────────────────────────────────────────────────
LEDGER_TAG = "가설기록"


def extract_ledger_json(text: str):
    """'가설기록: {...}' 줄(또는 ```json 블록)의 JSON 을 반환. 없거나 깨졌으면 None."""
    if not text:
        return None
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith(LEDGER_TAG):
            i, j = s.find("{"), s.rfind("}")
            if i != -1 and j > i:
                try:
                    return json.loads(s[i:j + 1])
                except (ValueError, TypeError):
                    return None
    m = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", text, re.S)
    if m:
        try:
            data = json.loads(m.group(1))
            return data if isinstance(data, dict) and "hypotheses" in data else None
        except (ValueError, TypeError):
            return None
    return None


def strip_ledger_json(text: str) -> str:
    """사람에게 보여 줄 분석 텍스트에서 기계용 '가설기록' 줄을 뺀다."""
    return "\n".join(ln for ln in (text or "").splitlines()
                     if not ln.strip().startswith(LEDGER_TAG)).strip()


_LINE_RE = re.compile(
    r"^\s*[-*]?\s*(H\d{1,2})\s*(?:\[\s*우선\s*[:：]\s*(상|중|하)\s*\])?\s*[:：.)]?\s*(.+)$")


def parse_hypothesis_lines(text: str) -> list[dict]:
    """'H1 [우선:상] (가설) — 근거 · 확인: X · 기각 시: Y' 형식의 줄을 가설 dict 로(폴백)."""
    out: list[dict] = []
    for ln in (text or "").splitlines():
        m = _LINE_RE.match(ln)
        if not m:
            continue
        hid, prio, rest = m.group(1).upper(), m.group(2) or "", m.group(3)
        parts = [p.strip() for p in re.split(r"\s+·\s+", rest)]
        body = parts[0]
        check = fallback = ""
        for p in parts[1:]:
            if p.startswith("확인"):
                check = p.split(":", 1)[-1].split("：", 1)[-1].strip()
            elif p.startswith("기각"):
                fallback = p.split(":", 1)[-1].split("：", 1)[-1].strip()
        text_ = re.split(r"\s+—\s+", body, maxsplit=1)[0].strip("() ")
        if text_:
            out.append({"id": hid, "text": text_, "priority": prio,
                        "check": check, "fallback": fallback})
    return out
