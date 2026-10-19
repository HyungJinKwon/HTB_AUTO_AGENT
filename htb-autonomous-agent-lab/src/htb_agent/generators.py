"""
generators — 익스플로잇 루프의 후보 생성원
===========================================

`exploit_loop.ExploitLoop` 에 주입하는 `Generator`(= `loop -> list[Candidate]`)
들을 만든다. 설계 원칙은 **기존 오픈소스 도구를 골라 돌린다**는 것 하나다 —
도구를 새로 짜지 않고 설치된 것(`tools/registry.py`)에서 고른다.

지금 두 생성원:
  - `make_llm_generator`  — LLM 이 단계·관측·죽은 가설을 보고 '어떤 도구를
    어떻게 돌릴지'를 expected 와 함께 제안한다. Hard 머신의 본 엔진.
  - `make_flag_generator` — 자격증명이 있으면 기존 원격 도구로 user.txt/root.txt 를
    읽는 결정적(deterministic) 후보. LLM 없이도 동작.

둘 다 매 라운드 `loop.ledger` 를 읽어 **이미 죽은 가설·획득한 Foothold** 를
반영한다. 같은 시도 반복을 막고, Foothold 가 생기면 다음 수가 바뀐다.
"""

from __future__ import annotations

from typing import Callable

from .attempt import Candidate
from .creds import CredentialVault
from .llm.router import BudgetExhausted
from .tiering import tier_for
from .verify import is_capability

# loop 타입은 런타임 임포트(순환 방지). Generator 시그니처만 맞춘다.
Generator = Callable[[object], list[Candidate]]


def make_llm_generator(llm_router, base_context: dict, target: str,
                       phase: str, max_items: int = 5) -> Generator:
    """LLM 후보 생성원. 매 호출 ledger 피드백(획득 접근·죽은 가설·없는 도구)을 얹는다."""
    def gen(loop) -> list[Candidate]:
        ctx = dict(base_context)
        # '능력' 만 — 확인된 사실(verified:)·플래그는 접근이 아니다
        caps = [f for f in loop.ledger.footholds() if is_capability(f)]
        if caps:
            ctx["footholds"] = caps
        # 시간순으로 넘긴다 — 최신순 정렬과 예산 안 절단은 라우터가 한다
        dead = [f"{label}: {why}" for label, why in loop.ledger.dead_hypotheses()]
        if dead:
            ctx["dead"] = dead
        missing = sorted(loop.missing_tools())
        if missing:
            ctx["unavailable"] = missing
        # 막힐수록(라운드↑) 더 센 티어. floor 는 라우터 기본 티어.
        rnd = max(0, getattr(loop.result, "rounds", 1) - 1)
        tier = tier_for(phase, round_idx=rnd, floor=llm_router.default_tier)
        try:
            return llm_router.suggest_candidates(ctx, target, phase, tier=tier,
                                                 max_items=max_items,
                                                 allow_shell=loop.channel is not None)
        except BudgetExhausted as e:
            loop.halt("토큰 예산 소진")
            loop.audit.event("budget_exhausted", error=str(e))
            return []
        except Exception as e:               # 백엔드 오류가 루프를 깨지 않는다
            loop.audit.event("llm_generator_error", error=str(e))
            return []
    return gen


# ── 플래그 캡처 (결정적) ──────────────────────────────────────────
# 자격증명으로 **원격 도구가 대상에서** 읽는다(netexec·ssh). 읽기 전용.
# user/root 는 반드시 명령을 분리한다 — 한 명령에서 둘을 읽으면 flag.classify_flag 가
# 'root.txt' 를 먼저 보고 user 플래그까지 root 로 분류한다.
#
# 셸 Foothold 로 `cat /home/*/user.txt` 를 직접 도는 분기는 두지 않는다: 대상 안의
# 셸 채널이 없으면 그 명령은 공격자 자신의 파일시스템을 읽는다(공허한 시도).
_CRED_FLAGS_WIN = [
    (r'netexec smb {t} -u {user} -p {pass} -x "type C:\Users\*\Desktop\user.txt"', "user"),
    (r'netexec smb {t} -u {user} -p {pass} -x "type C:\Users\Administrator\Desktop\root.txt"', "root"),
]
_CRED_FLAGS_NIX = [
    ("sshpass -p {pass} ssh -o StrictHostKeyChecking=no {user}@{t} 'cat /home/*/user.txt'", "user"),
    ("sshpass -p {pass} ssh -o StrictHostKeyChecking=no {user}@{t} 'cat /root/root.txt'", "root"),
]


def make_flag_generator(vault: CredentialVault | None, target: str,
                        os_class: str = "", phase: str = "privesc") -> Generator:
    """자격증명이 있으면 기존 원격도구(netexec·ssh)로 플래그를 읽는 후보.

    자격증명이 없으면 빈 목록 → 루프는 다른 생성원으로.
    """
    is_win = "windows" in (os_class or "").lower()
    cred_tmpls = _CRED_FLAGS_WIN if is_win else _CRED_FLAGS_NIX

    def gen(loop) -> list[Candidate]:
        out: list[Candidate] = []
        if vault is not None and vault.creds:
            for tmpl, kind in cred_tmpls:
                for cmd, runnable in vault.expand(tmpl, target):
                    if runnable:
                        out.append(_flag_cand(cmd, kind, phase))
        return out
    return gen


def _flag_cand(cmd: str, kind: str, phase: str) -> Candidate:
    return Candidate(surface=f"{phase}:flag", summary=f"flag:{kind} 읽기",
                     commands=[cmd], expected=f"flag:{kind}", source="kb",
                     est_seconds=20)
