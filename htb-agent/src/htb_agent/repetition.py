"""
Repetition Identifier — 반복·정체 감지 (실행 트레이스 사후 분석, 사람 보고용)
==============================================================================

AutoPentester 류가 말하는 'Repetition Identifier'를 이 도구의 승인제 구조에 맞춘
형태. 같은 작업이 반복되거나 한 지점에서 정체되는 것을 **감지해 사람에게 보고**한다.
목적은 두 가지다.

  1. 효율 — 사실상 같은 명령/같은 실패가 되풀이되는 구간을 짚어, 낭비를 사람이 끊게 한다.
  2. 깊이 우선 함정 완화(보고 측면) — 한 경로에 매달려 같은 실패를 반복 중임을 드러내,
     사람이 다른 각도를 택하도록 돕는다.

이 모듈은 **판단 재료만** 만든다. 다음 명령을 자동으로 바꾸거나 경로를 재계획하지
않는다(그 결정은 사람). 네트워크·상태 변경 없음.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field

from .util import binary_of

# 명령 정규화 — 바이너리 + 정렬된 '의미 있는' 플래그(값 제거)로 서명(signature)을 만든다.
# 워드리스트 경로·포트·출력파일 등 가변 인자는 떨궈, '같은 종류의 시도'를 묶는다.
_VALUE_FLAG = re.compile(r"^-")


@functools.lru_cache(maxsize=4096)
def signature(cmd: str) -> str:
    """명령의 '종류' 서명. 바이너리 + 플래그 이름들(값 제외, 정렬). 대상/워드리스트 등
    가변 토큰은 무시 → 사실상 동일한 시도를 같은 서명으로 묶는다."""
    try:
        import shlex
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    binary = binary_of(cmd, strip_path=True)
    flags: set[str] = set()
    for t in toks:
        if _VALUE_FLAG.match(t):
            # --wordlist=foo → --wordlist, -p 80 의 '-p' 만 남긴다
            flags.add(t.split("=", 1)[0])
    return binary + " " + " ".join(sorted(flags))


@dataclass
class RepetitionReport:
    repeated_cmds: list[tuple[str, int]] = field(default_factory=list)   # (서명, 횟수)
    repeated_failures: list[tuple[str, int]] = field(default_factory=list)  # (실패범주, 횟수)
    stalled: bool = False       # 실행은 많으나 유의미한 출력이 거의 없음 → 정체
    note: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.repeated_cmds or self.repeated_failures or self.stalled)


def analyze(findings, blockers=None, *, cmd_threshold: int = 3,
            fail_threshold: int = 3) -> RepetitionReport:
    """실행 트레이스(findings)와 진단(blockers)에서 반복·정체를 감지한다.
    - findings: EnumFinding 류(command, ran, output 속성).
    - blockers: (command, FailureDiagnosis) 목록(없으면 생략).
    - cmd_threshold: 같은 서명 명령이 이 횟수 이상이면 '반복'으로 표시.
    - fail_threshold: 같은 실패 범주가 이 횟수 이상이면 '반복 실패'로 표시."""
    rep = RepetitionReport()
    findings = list(findings or [])

    # 1) 반복 명령(같은 서명) — 실제 실행된 것만 집계(게이트 탈락은 제외)
    sig_counts: dict[str, int] = {}
    ran = [f for f in findings if getattr(f, "ran", False)]
    for f in ran:
        s = signature(getattr(f, "command", ""))
        sig_counts[s] = sig_counts.get(s, 0) + 1
    rep.repeated_cmds = sorted(
        ((s, n) for s, n in sig_counts.items() if n >= cmd_threshold),
        key=lambda x: -x[1])

    # 2) 반복 실패(같은 진단 범주) — 환경·대상 구분 없이 '같은 벽에 반복해서 부딪힘'
    if blockers:
        fail_counts: dict[str, int] = {}
        for _cmd, diag in blockers:
            cat = getattr(diag, "category", "")
            if cat:
                fail_counts[cat] = fail_counts.get(cat, 0) + 1
        rep.repeated_failures = sorted(
            ((c, n) for c, n in fail_counts.items() if n >= fail_threshold),
            key=lambda x: -x[1])

    # 3) 정체 — 실행은 여러 번인데 유의미한 출력이 거의 없음(전부 빈/실패)
    if len(ran) >= cmd_threshold:
        useful = sum(1 for f in ran if getattr(f, "output", ""))
        if useful <= max(1, len(ran) // 5):
            rep.stalled = True

    if rep.has_findings:
        bits = []
        if rep.repeated_cmds:
            bits.append(f"반복 명령 {len(rep.repeated_cmds)}종")
        if rep.repeated_failures:
            bits.append(f"반복 실패 {len(rep.repeated_failures)}종")
        if rep.stalled:
            bits.append("정체(유의미한 출력 희박)")
        rep.note = " · ".join(bits)
    return rep
