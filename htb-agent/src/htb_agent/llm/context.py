"""
context — LLM 프롬프트 조립: 예산·우선순위·'채우지 않기'
=========================================================

(출처: 해커톤 포크 `pokochy/htb-autonomous-agent-lab` 의 `llm/context.py` 를 루트 htb-agent
로 이식. 팀 내부 파생 코드. 외부 의존성 없음 — `math`/`dataclasses` 표준 라이브러리만.)

목표는 컨텍스트를 **꽉 채우는 것이 아니라 결정에 필요한 만큼만** 넣는 것이다.

  - 비용은 입력 토큰에 선형이고, 긴 컨텍스트는 정확도도 떨어뜨린다(관련 없는 줄이
    관련 있는 줄을 희석한다). 1M 창을 가진 모델에서도 한 번의 후보 생성에 필요한
    신호는 3~4k 토큰이면 충분하다. 창 크기는 예산이 아니라 **안전 여유**일 뿐이다.
  - 로컬 모델은 창이 작고, 넘치면 오류 없이 앞부분(시스템 프롬프트)이 잘린다.

그래서 숫자 세 개로 운영한다.

    target   정상 운영점(소프트). 이 아래에서는 **절대 패딩하지 않는다.**
    ceiling  하드 상한. 넘으면 필수 구역의 꼬리까지 깎는다.
    fixed    시스템 프롬프트 등 이미 쓴 몫(예산에서 먼저 뺀다).

구역(Section)은 우선순위(priority)와 렌더 순서(order)를 **따로** 갖는다. 우선순위는
'살아남는 순서'(0=필수, 클수록 먼저 버림), 순서는 '프롬프트에 놓이는 위치'다.
정적인 것을 앞에, 자주 변하는 것·결정에 직결된 것(실패한 가설)을 끝에 두면 접두사
캐시에도 유리하고, 긴 컨텍스트의 중간 망각(lost-in-the-middle)도 줄어든다.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

MAX_LINE_CHARS = 240      # 한 줄이 구역을 통째로 잡아먹는 것을 막는 상한


def est_tokens(text: str) -> int:
    """토큰 수 추정(순수 파이썬, 보수적 = 과대추정).

    ASCII 3자/토큰(명령·경로는 산문보다 촘촘), 한글·한자·가나 1자/토큰, 그 외 2자/토큰.
    과대추정은 '덜 채우는' 쪽의 오차라 안전하다. 정확한 값이 필요하면 사용량(usage)을
    쓰고, 이 함수는 예산 배분용이다.
    """
    if not text:
        return 0
    wide = ascii_ = 0
    for ch in text:
        o = ord(ch)
        if o < 128:
            ascii_ += 1
        elif (0x1100 <= o <= 0x11FF or 0x3040 <= o <= 0x30FF or 0x3130 <= o <= 0x318F
              or 0xAC00 <= o <= 0xD7AF or 0x4E00 <= o <= 0x9FFF):
            wide += 1
    other = len(text) - wide - ascii_
    return math.ceil(ascii_ / 3.0 + wide * 1.0 + other / 2.0)


@dataclass
class Section:
    name: str
    lines: list[str]
    priority: int           # 0 = 필수(절대 안 버림) … 클수록 먼저 버림
    order: int              # 렌더 위치(작을수록 앞)
    title: str = ""
    cap: int = 0            # 구역 토큰 상한(0 = 없음). 앞쪽(= 중요한) 줄만 남긴다
    dropped: int = 0

    def tokens(self) -> int:
        if not self.lines:
            return 0
        extra = 1 if self.dropped else 0
        return est_tokens(self.title) + sum(est_tokens(ln) + 1 for ln in self.lines) + extra * 4

    def render(self) -> str:
        if not self.lines:
            return ""
        body = list(self.lines)
        if self.dropped:
            body.append(f"…(+{self.dropped} omitted)")
        return "\n".join(([self.title] if self.title else []) + body)


@dataclass
class Built:
    text: str
    tokens: int             # 시스템(fixed) 포함 추정 총량
    report: dict = field(default_factory=dict)


class ContextBuilder:
    def __init__(self, max_line_chars: int = MAX_LINE_CHARS):
        self.max_line_chars = max_line_chars
        self._sections: list[Section] = []

    def add(self, name: str, lines: list[str], *, priority: int, order: int,
            title: str = "", cap: int = 0) -> None:
        clean = []
        for ln in lines or []:
            ln = " ".join(str(ln).split())              # 개행·연속공백 정리
            if not ln:
                continue
            if len(ln) > self.max_line_chars:
                ln = ln[: self.max_line_chars - 1] + "…"
            clean.append(ln)
        sec = Section(name, clean, priority, order, title, cap)
        # 구역 상한 — 앞쪽 줄이 중요하다는 규약(호출자가 중요한 것부터 넣는다)
        while sec.cap and sec.tokens() > sec.cap and len(sec.lines) > 1:
            sec.lines.pop()
            sec.dropped += 1
        self._sections.append(sec)

    def _total(self, fixed: int) -> int:
        return fixed + sum(s.tokens() for s in self._sections)

    def build(self, target: int, ceiling: int, fixed: int = 0) -> Built:
        secs = self._sections
        total = self._total(fixed)

        # 1) 목표까지 덜어낸다 — 중요도가 가장 낮은 계층부터, 계층 안에서는 가장 큰
        #    구역의 꼬리(가장 덜 중요한 줄)부터. 한 계층을 비우기 전엔 윗계층을 안 건드린다.
        for prio in sorted({s.priority for s in secs if s.priority > 0}, reverse=True):
            tier = [s for s in secs if s.priority == prio]
            while total > target and any(s.lines for s in tier):
                s = max((x for x in tier if x.lines), key=lambda x: x.tokens())
                s.lines.pop()
                s.dropped += 1
                total = self._total(fixed)
            if total <= target:
                break

        # 2) 필수 구역만으로도 상한을 넘으면 마지막 수단으로 필수 구역의 꼬리를 깎는다.
        #    (첫 줄 = 대상/단계 정보는 남긴다.)
        if total > ceiling:
            for s in sorted((x for x in secs if x.priority == 0), key=lambda x: -x.tokens()):
                while total > ceiling and len(s.lines) > 1:
                    s.lines.pop()
                    s.dropped += 1
                    total = self._total(fixed)

        parts = [s.render() for s in sorted(secs, key=lambda x: x.order) if s.lines]
        text = "\n\n".join(parts)
        report = {
            "tokens": total, "fixed": fixed, "target": target, "ceiling": ceiling,
            "over_target": total > target,
            "kept": {s.name: len(s.lines) for s in secs if s.lines},
            "dropped": {s.name: s.dropped for s in secs if s.dropped},
        }
        return Built(text, total, report)
