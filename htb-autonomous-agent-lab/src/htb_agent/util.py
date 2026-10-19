"""공용 유틸리티."""

from __future__ import annotations

import re
import shlex


def binary_of(command: str, strip_path: bool = False) -> str:
    """
    명령에서 실제 바이너리 토큰을 추출(선행 환경변수 할당 NAME=VALUE 는 건너뜀).
    strip_path=True 면 경로를 제거한 basename 반환.
    """
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for t in toks:
        if "=" in t and not t.startswith("-"):
            continue
        return t.rsplit("/", 1)[-1] if strip_path else t
    return ""


_URL_PORT = re.compile(r"\b(https?|ftp)://[^/\s:]+(?::(\d+))?", re.I)
_DEFAULT_PORT = {"http": "80", "https": "443", "ftp": "21"}
_FLAG_PORT = re.compile(r"(?:^|\s)-p\s*(\d{1,5})\b")


def surface_of(command: str, phase: str) -> str:
    """명령 → 접근면 이름. 포트·프로토콜까지 구분한다.

    `phase:binary` 만 쓰면 LLM 이 거의 모든 걸 curl 로 하므로 서로 다른 서비스가 한
    접근면으로 뭉치고, 반증 3번이면 curl 계열 전체가 '소진'돼 맞는 경로까지 버려진다.
    """
    m = _URL_PORT.search(command)
    if m:
        scheme = m.group(1).lower()
        return f"{scheme}:{m.group(2) or _DEFAULT_PORT[scheme]}"
    binary = binary_of(command, strip_path=True) or "cmd"
    p = _FLAG_PORT.search(command)
    return f"{phase}:{binary}" + (f":{p.group(1)}" if p else "")
