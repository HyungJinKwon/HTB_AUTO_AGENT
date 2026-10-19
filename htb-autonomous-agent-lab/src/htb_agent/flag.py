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

# 플래그 파일을 읽는 명령으로 보이는 단서
_FLAG_FILE_HINTS = ("user.txt", "root.txt", "flag.txt", "proof.txt", "local.txt")


@dataclass
class FlagHit:
    value: str
    kind: str          # user / root / unknown
    source: str        # 발견된 명령
    provenance: str = ""   # genuine / undemonstrated (ctf-abacus 획득경로)


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


def classify_flag(command: str) -> str:
    """명령 맥락으로 user/root 분류. 파일명을 사용자명보다 우선(오분류 방지)."""
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


def scan(command: str, output: str) -> list[FlagHit]:
    """명령 + 출력에서 플래그를 찾아 분류. (오탐 방지 조건 적용)"""
    hits: list[FlagHit] = []
    seen: set[str] = set()
    # TAG{...} 형식은 항상 플래그로 간주
    for v in extract_flags(output, require_fmt=True):
        if v not in seen:
            seen.add(v)
            hits.append(FlagHit(v, classify_flag(command), command))
    # 32-hex 는 플래그 파일을 읽는 명령 맥락일 때만
    if is_flag_command(command):
        for v in extract_flags(output):
            if v not in seen:
                seen.add(v)
                hits.append(FlagHit(v, classify_flag(command), command))
    return hits
