"""공용 유틸리티."""

from __future__ import annotations

import shlex

# 실제 도구 앞에 붙는 래퍼(그 자체는 도구가 아님) — skip_wrappers=True 일 때만 건너뛴다.
# 래퍼의 선행 옵션(-u user 등)도 함께 건너뛴다. 여기 없는 토큰을 만나면 즉시 바이너리로 본다.
_WRAPPERS = frozenset({"sudo", "doas", "proxychains", "proxychains4", "stdbuf", "nice", "ionice"})


def binary_of(command: str, strip_path: bool = False, skip_wrappers: bool = False) -> str:
    """
    명령에서 실제 바이너리 토큰을 추출(선행 환경변수 할당 NAME=VALUE 는 건너뜀).
    strip_path=True 면 경로를 제거한 basename 반환.
    skip_wrappers=True 면 sudo/proxychains 등 래퍼(+그 선행 옵션)를 건너뛰고 실제 도구를 반환.
    """
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if "=" in t and not t.startswith("-"):
            i += 1
            continue
        if skip_wrappers and t.rsplit("/", 1)[-1] in _WRAPPERS:
            i += 1
            while i < len(toks) and toks[i].startswith("-"):   # 래퍼 자체 옵션 건너뜀
                i += 1
            continue
        return t.rsplit("/", 1)[-1] if strip_path else t
    return ""


def binary_index(toks: list[str], skip_wrappers: bool = True) -> int:
    """토큰 리스트에서 실제 바이너리 토큰의 인덱스를 찾는다(env-prefix·래퍼 건너뜀).
    없으면 len(toks) 반환. `_insert_flag` 처럼 '바이너리 바로 뒤'가 필요한 곳에서 쓴다."""
    i = 0
    while i < len(toks):
        t = toks[i]
        if "=" in t and not t.startswith("-"):
            i += 1
            continue
        if skip_wrappers and t.rsplit("/", 1)[-1] in _WRAPPERS:
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 1
            continue
        return i
    return len(toks)


def network_blocked() -> bool:
    """실제 아웃바운드 네트워크를 전역으로 차단할지(환경변수). 테스트·CI 가 ASSASSIN_NO_NET=1 로
    설정하면 기본 fetcher 들이 실제 요청을 보내지 않는다(주입된 가짜 fetcher 는 영향 없음)."""
    import os
    return os.environ.get("ASSASSIN_NO_NET", "").strip().lower() in ("1", "true", "yes", "on")


def http_get_text(url: str, timeout: int = 10,
                  user_agent: str = "assassin/1.0") -> str | None:
    """urllib 기반 단순 GET → 텍스트(프록시 env 존중). network_blocked()·실패 시 None.
    enrich/learn 등의 기본 fetcher 공용 구현(중복 제거) — 호출부가 allowlist 로 URL 을 거른다."""
    if network_blocked():
        return None
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (호출부 allowlist)
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None
