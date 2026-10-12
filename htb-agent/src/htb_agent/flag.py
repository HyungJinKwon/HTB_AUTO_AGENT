"""
Flag Capture — HTB user.txt / root.txt 플래그 탐지·분류
========================================================

HTB 머신의 목표는 user.txt(일반 사용자)·root.txt(관리자) 플래그 획득이다.
이 모듈은 (1) 명령 출력에서 플래그 형식을 추출하고, (2) 명령 맥락으로
user/root 를 분류한다. 플래그는 보통 32자리 hex 또는 `HTB{...}` 형식이다.

오탐 방지: 32-hex 는 다른 해시일 수 있으므로, 플래그로 기록하는 조건은
  - 값이 `TAG{...}` 형식이거나
  - 명령이 플래그 파일(user.txt/root.txt/proof.txt 등)을 읽는 맥락일 때
로 제한한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 32자리 hex (HTB 플래그 통상 형식)
_FLAG_HEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
# TAG{...} 형식 (HTB{...}, FLAG{...}, CTF{...} 등)
_FLAG_FMT = re.compile(r"\b[A-Za-z0-9_]{2,10}\{[^}\r\n]{1,200}\}")

# 잘 알려진 플래그 TAG(소문자). `TAG{...}` 를 플래그로 '신뢰'하는 기준 — 이 집합 또는 호출부가
# 지정한 prefixes 에 속하거나, 플래그 파일을 읽는 맥락일 때만. (CSS `header{display:none}`·코드
# `obj{...}` 같은 임의 `word{...}` 를 exploit-derived 가짜 플래그로 기록하던 과매칭 방지 — 정직성 §3)
_KNOWN_FLAG_TAGS = frozenset({
    "htb", "flag", "ctf", "key", "dh", "dreamhack", "picoctf", "thm", "nf", "pctf",
})

# 플래그 파일을 읽는 명령으로 보이는 단서
_FLAG_FILE_HINTS = ("user.txt", "root.txt", "flag.txt", "proof.txt", "local.txt")


@dataclass
class FlagHit:
    value: str
    kind: str          # user / root / unknown
    source: str        # 발견된 명령


def extract_flags(text: str, require_fmt: bool = False) -> list[str]:
    """출력에서 플래그 후보 추출(중복 제거). require_fmt=True 면 TAG{...}만."""
    if not text:
        return []
    hits: set[str] = set(_FLAG_FMT.findall(text))
    if not require_fmt:
        hits |= {m.lower() for m in _FLAG_HEX.findall(text)}
    return sorted(hits)


def is_flag_command(command: str) -> bool:
    """명령이 플래그 파일을 읽는 맥락인지."""
    c = command.lower()
    return any(h in c for h in _FLAG_FILE_HINTS) or "desktop" in c


def classify_flag(command: str, flag_kind: str = "boot2root") -> str:
    """
    명령 맥락으로 플래그 분류. 파일명을 사용자명보다 우선(오분류 방지).
    flag_kind="single"(CTF/Dreamhack Jeopardy) 이면 user/root 구분 없이 "flag".
    """
    if flag_kind == "single":
        return "flag"
    c = command.lower()
    # 1) 명시적 플래그 파일명 우선
    if "root.txt" in c or "proof.txt" in c:
        return "root"
    if "user.txt" in c or "local.txt" in c:
        return "user"
    # 2) 경로 단서
    if "/root/" in c:
        return "root"
    if "/home/" in c or "desktop" in c:
        return "user"
    # 3) 마지막으로 관리자 계정 단서
    if "administrator" in c:
        return "root"
    return "unknown"


def scan(command: str, output: str, flag_kind: str = "boot2root",
         prefixes: tuple[str, ...] = ()) -> list[FlagHit]:
    """
    명령 + 출력에서 플래그를 찾아 분류. (오탐 방지 조건 적용)
      - flag_kind : boot2root(user/root) | single(CTF flag 1개)
      - prefixes  : 우선 인식할 TAG{} 접두(예: ('DH','flag')). 지정 시 해당 접두
                    플래그를 먼저/확실히 기록(오탐 감소). 32-hex 은 boot2root 에서만.
    """
    hits: list[FlagHit] = []
    seen: set[str] = set()
    fmt_hits = extract_flags(output, require_fmt=True)
    # 접두 지정 시 매칭 접두를 앞세움(정렬 안정)
    pref_l = tuple(p.lower() for p in prefixes)
    if prefixes:
        fmt_hits = ([v for v in fmt_hits if v.split("{", 1)[0].lower() in pref_l]
                    + [v for v in fmt_hits if v.split("{", 1)[0].lower() not in pref_l])
    # `TAG{...}` 는 TAG 가 (알려진 플래그 태그 ∪ 지정 접두)에 속하거나, 플래그 파일을 읽는
    # 맥락일 때만 신뢰한다. 그 외 임의 `word{...}`(CSS·코드 등)는 가짜 플래그로 기록하지 않는다
    # (정직성 §3 — 과거엔 'TAG{...} 항상 플래그'라 웹 enum 출력의 CSS 가 genuine 으로 오기록됐다).
    allowed_tags = _KNOWN_FLAG_TAGS | set(pref_l)
    flag_ctx = is_flag_command(command)
    for v in fmt_hits:
        if v.split("{", 1)[0].lower() not in allowed_tags and not flag_ctx:
            continue
        if v not in seen:
            seen.add(v)
            hits.append(FlagHit(v, classify_flag(command, flag_kind), command))
    # 32-hex 는 boot2root(HTB) + 플래그 파일 맥락일 때만(CTF single 에선 제외: 해시 오탐↓)
    if flag_kind != "single" and is_flag_command(command):
        for v in extract_flags(output):
            if v not in seen:
                seen.add(v)
                hits.append(FlagHit(v, classify_flag(command, flag_kind), command))
    return hits
