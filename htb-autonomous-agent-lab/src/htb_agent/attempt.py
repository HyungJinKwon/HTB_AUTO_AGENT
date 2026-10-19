"""
attempt — 가설·시도 원장 (익스플로잇 루프의 기반)
==================================================

`docs/EXPLOIT-LOOP.md` 의 상태 모델을 자료구조로 고정한다. 이 모듈의 존재
이유는 저장이 아니라 **두 가지 규율을 코드로 강제**하는 것이다.

1. **검증 불가한 후보를 만들 수 없다.** `Candidate` 는 `expected`(성공 시
   관측될 것)를 반드시 선언한다. "일단 돌려보고 출력을 보자"를 금지한다.

2. **근거 없는 `refuted` 는 없다.** 근거를 못 적으면 `inconclusive` 로 강등되고,
   전제조건 미충족은 애초에 `refuted` 가 될 수 없다. 이 둘을 뭉개는 것이
   에이전트가 **맞는 접근면을 일찍 버리는** 주된 원인이다.

원장은 재분석(L4) 입력이자 라이트업 원본이자 감사 증빙이다.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field

VERDICTS = ("confirmed", "refuted", "inconclusive")

DEFAULT_MAX_RETRIES = 2    # inconclusive 재시도 상한 (가설당)
DEFAULT_REFUTE_CAP = 3     # 접근면당 refuted 상한 → 접근면 소진


class CandidateError(ValueError):
    """검증 불가·실행 불가한 후보."""


@dataclass
class Candidate:
    """실행 후보. 선언이 불완전하면 생성 자체가 실패한다."""
    surface: str                    # 접근면 (예: "http:8080", "smb:445", "privesc:local")
    summary: str                    # 사람이 읽을 한 줄
    commands: list[str]
    expected: str                   # 성공 시 관측될 것 — 검증이 이걸 본다
    preconditions: list[str] = field(default_factory=list)
    irreversible: bool = False      # 서비스 재시작·계정 잠금·파일 덮어쓰기 등
    est_seconds: int = 60
    source: str = "kb"              # kb | cve | llm
    hid: str = ""
    # 성공이 확인되면 얻는 '접근 능력'(예: webshell, ssh-bob). 비어 있으면 확인된
    # '사실'일 뿐이라 Foothold 로 치지 않는다 — 배너 한 줄 확인이 접근 획득으로
    # 보고되고 플래그가 genuine 으로 둔갑하는 것을 막는다.
    grants: str = ""

    def __post_init__(self) -> None:
        if not self.expected.strip():
            raise CandidateError(
                f"[{self.surface}] expected 미선언 — 검증 불가한 후보는 금지")
        if not self.commands:
            raise CandidateError(f"[{self.surface}] commands 비어 있음")
        if not self.surface.strip():
            raise CandidateError("surface 미지정")
        if not self.hid:
            self.hid = "h" + uuid.uuid4().hex[:8]
        # grants 는 LLM 이 쓴 문자열(신뢰 불가). 콜론을 제거해 `flag:`·`verified:`
        # 접두사로 능력을 위장하지 못하게 한다 — is_capability() 가 이 접두사로 판별.
        self.grants = re.sub(r"[^\w.-]", "", self.grants or "")[:40]


@dataclass
class Attempt:
    """후보 1개에 대한 실행 1회 + 판정."""
    hid: str
    surface: str
    commands: list[str]
    expected: str
    observed: str = ""
    verdict: str = "inconclusive"
    because: str = ""               # refuted 면 필수
    precond_ok: bool = True
    seconds: float = 0.0
    foothold: str | None = None     # confirmed 일 때 획득한 능력
    coerced: str = ""               # 강등된 경우 그 사유(원래 판정 보존)
    provenance: str = ""            # 플래그 획득 경로 (genuine/undemonstrated)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"알 수 없는 판정: {self.verdict!r} (가능: {VERDICTS})")
        # 규율 2-a: 전제조건 미충족은 가설 반증이 아니다
        if not self.precond_ok and self.verdict == "refuted":
            self.coerced = "refuted → inconclusive: 전제조건 미충족은 가설 반증이 아님"
            self.verdict = "inconclusive"
        # 규율 2-b: 근거 없는 refuted 는 인정하지 않는다
        elif self.verdict == "refuted" and not self.because.strip():
            self.coerced = "refuted → inconclusive: 근거(because) 미기록"
            self.verdict = "inconclusive"
        # confirmed 는 획득한 능력을 반드시 적는다 (증거 없는 성공 주장 금지)
        if self.verdict == "confirmed" and not (self.foothold or "").strip():
            self.coerced = "confirmed → inconclusive: foothold(획득 능력) 미기록"
            self.verdict = "inconclusive"


class Ledger:
    """시도 이력. 접근면 소진·재시도 상한·중복 명령을 판정한다."""

    def __init__(self, max_retries: int = DEFAULT_MAX_RETRIES,
                 refute_cap: int = DEFAULT_REFUTE_CAP) -> None:
        self.max_retries = max_retries
        self.refute_cap = refute_cap
        self._attempts: list[Attempt] = []
        self._summaries: dict[str, str] = {}   # hid → summary (사후 설명용)

    # ── 기록 ─────────────────────────────────────────────────────────
    def record(self, a: Attempt, summary: str = "") -> Attempt:
        self._attempts.append(a)
        if summary:
            self._summaries.setdefault(a.hid, summary)
        return a

    # ── 조회 ─────────────────────────────────────────────────────────
    def attempts(self, surface: str | None = None) -> list[Attempt]:
        if surface is None:
            return list(self._attempts)
        return [a for a in self._attempts if a.surface == surface]

    def count(self, verdict: str, surface: str | None = None) -> int:
        return sum(1 for a in self.attempts(surface) if a.verdict == verdict)

    def footholds(self) -> list[str]:
        return [a.foothold for a in self._attempts
                if a.verdict == "confirmed" and a.foothold]

    def solved(self, surface: str) -> bool:
        return self.count("confirmed", surface) > 0

    def surfaces(self) -> list[str]:
        out: list[str] = []
        for a in self._attempts:
            if a.surface not in out:
                out.append(a.surface)
        return out

    # ── 판정 규칙 ────────────────────────────────────────────────────
    def surface_exhausted(self, surface: str) -> bool:
        """접근면을 내려도 되는가 — refuted 가 상한에 도달했고 성과가 없을 때."""
        if self.solved(surface):
            return False
        return self.count("refuted", surface) >= self.refute_cap

    def retryable(self, hid: str) -> bool:
        """inconclusive 재시도 여력이 남았는가."""
        mine = [a for a in self._attempts if a.hid == hid]
        if any(a.verdict == "confirmed" for a in mine):
            return False
        if any(a.verdict == "refuted" for a in mine):
            return False
        return sum(1 for a in mine if a.verdict == "inconclusive") < self.max_retries

    def retry_queue(self) -> list[str]:
        seen: list[str] = []
        for a in self._attempts:
            if a.verdict == "inconclusive" and a.hid not in seen and self.retryable(a.hid):
                seen.append(a.hid)
        return seen

    def already_ran(self, command: str) -> bool:
        """같은 명령을 그대로 또 돌리지 않게."""
        return any(command in a.commands for a in self._attempts)

    # ── 재분석 입력 (L4 → L1) ───────────────────────────────────────
    def dead_hypotheses(self) -> list[tuple[str, str]]:
        """반증된 가설 (설명, 근거). 컨텍스트로 되올려 같은 시도 반복을 막는다."""
        out: list[tuple[str, str]] = []
        for a in self._attempts:
            if a.verdict != "refuted":
                continue
            label = self._summaries.get(a.hid) or f"{a.surface} ({a.hid})"
            if (label, a.because) not in out:
                out.append((label, a.because))
        return out

    def untouched(self, known_surfaces: list[str]) -> list[str]:
        """아직 시도하지 않은 접근면 — 포기 리포트와 체크포인트에 쓴다."""
        tried = set(self.surfaces())
        return [s for s in known_surfaces if s not in tried]

    def summary(self) -> str:
        total = len(self._attempts)
        parts = [f"{v}={self.count(v)}" for v in VERDICTS]
        fh = self.footholds()
        line = f"시도 {total}건 | " + " ".join(parts)
        if fh:
            line += f" | 획득: {', '.join(fh)}"
        spent = sum(a.seconds for a in self._attempts)
        return line + f" | 소요 {spent:.0f}s"

    # ── 영속 (state.py / audit.py 와 함께) ──────────────────────────
    def to_dict(self) -> dict:
        return {"max_retries": self.max_retries, "refute_cap": self.refute_cap,
                "summaries": dict(self._summaries),
                "attempts": [asdict(a) for a in self._attempts]}

    @classmethod
    def from_dict(cls, d: dict) -> "Ledger":
        led = cls(max_retries=d.get("max_retries", DEFAULT_MAX_RETRIES),
                  refute_cap=d.get("refute_cap", DEFAULT_REFUTE_CAP))
        led._summaries = dict(d.get("summaries") or {})
        for raw in d.get("attempts") or []:
            raw = dict(raw)
            raw.pop("coerced", None)      # 재구성 시 규율을 다시 적용
            led._attempts.append(Attempt(**raw))
        return led
