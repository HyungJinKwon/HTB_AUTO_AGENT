"""공용 유틸리티."""

from __future__ import annotations

import shlex

# 실제 도구 앞에 붙는 래퍼(그 자체는 도구가 아님) → 각 래퍼가 '값을 받는' 자체 옵션 집합.
# skip_wrappers=True 일 때 래퍼와 그 선행 옵션(값 받는 옵션은 값 토큰까지)을 건너뛴다.
# 값 받는 옵션만 다음 토큰을 소비한다 — sudo `-n`(비대화·boolean) 과 nice `-n N`(값)이 달라
# 래퍼별로 분리해야 'sudo -u www-data cat'·'nice -n 10 nmap' 에서 실제 도구를 정확히 집는다.
_WRAPPER_VALUE_OPTS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R"}),  # -n 은 boolean
    "doas": frozenset({"-u", "-C"}),
    "proxychains": frozenset({"-f"}), "proxychains4": frozenset({"-f"}),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
}
_WRAPPERS = frozenset(_WRAPPER_VALUE_OPTS)   # 하위호환 — 래퍼 이름 집합(멤버십용)


def _skip_wrappers(toks: list[str], i: int) -> int:
    """toks[i] 부터 선행 env-할당·래퍼(+그 옵션/값)를 건너뛴 뒤의 인덱스를 반환.
    값 받는 옵션은 값 토큰까지 소비한다(래퍼별 _WRAPPER_VALUE_OPTS 기준)."""
    n = len(toks)
    while i < n:
        t = toks[i]
        if "=" in t and not t.startswith("-"):   # 선행 환경변수 할당 NAME=VALUE
            i += 1
            continue
        base = t.rsplit("/", 1)[-1]
        if base in _WRAPPER_VALUE_OPTS:
            value_opts = _WRAPPER_VALUE_OPTS[base]
            i += 1
            while i < n and toks[i].startswith("-"):
                opt = toks[i]
                i += 1
                # 값 받는 옵션이면 값 토큰 1개도 소비(단, '--opt=val' 처럼 '=' 포함이면 단독 소비)
                if opt in value_opts and "=" not in opt and i < n and not toks[i].startswith("-"):
                    i += 1
            continue
        break
    return i


def binary_of(command: str, strip_path: bool = False, skip_wrappers: bool = False) -> str:
    """
    명령에서 실제 바이너리 토큰을 추출(선행 환경변수 할당 NAME=VALUE 는 건너뜀).
    strip_path=True 면 경로를 제거한 basename 반환.
    skip_wrappers=True 면 sudo/proxychains 등 래퍼(+그 선행 옵션·값)를 건너뛰고 실제 도구를 반환.
    """
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    i = _skip_wrappers(toks, 0) if skip_wrappers else 0
    while i < len(toks):
        t = toks[i]
        if "=" in t and not t.startswith("-"):   # skip_wrappers=False 경로의 env-할당 처리
            i += 1
            continue
        return t.rsplit("/", 1)[-1] if strip_path else t
    return ""


def binary_index(toks: list[str], skip_wrappers: bool = True) -> int:
    """토큰 리스트에서 실제 바이너리 토큰의 인덱스를 찾는다(env-prefix·래퍼 건너뜀).
    없으면 len(toks) 반환. `_insert_flag` 처럼 '바이너리 바로 뒤'가 필요한 곳에서 쓴다."""
    if skip_wrappers:
        return _skip_wrappers(toks, 0)
    i = 0
    while i < len(toks):
        if "=" in toks[i] and not toks[i].startswith("-"):
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
