"""
HTB 플랫폼 통합 — VPN 프리플라이트 + 플래그 자동제출 + 머신 스폰 (opt-in, 권한 확인 자산 한정)
================================================================================================

redcat2 의 'HTB 부트스트랩'(VPN·spawn·플래그 제출) 축을 이 도구의 안전 경계에 맞춰 이식한다.
**전부 opt-in** 이며 당신 자신의 HTB 계정 토큰으로 **권한 확인된 CTF 자산**에만 쓴다(§4).

안전·경계:
  · **토큰은 환경변수(`HTB_TOKEN`)에서만** 읽는다. 로그·오딧·출력에 절대 남기지 않는다.
  · 외부 전송 대상은 HTB API 뿐(사용자 이메일 등 무관 데이터 전송 없음).
  · 엔드포인트는 공개 클라이언트(pyhackthebox) 기준 — HTB 가 예고 없이 바꿀 수 있어
    `HTB_API_BASE` 로 덮어쓰기 가능(확인되지 않은 값은 지어내지 않음 — 검증된 경로만 기본값).
  · HTTP 계층은 주입 가능(테스트는 네트워크 없이 요청 구성만 검증).

검증된 v4 경로(pyhackthebox 클라이언트 소스 기준):
  · 플래그 제출: POST machine/own  {"flag","id","difficulty"(10~100)}
  · 머신 스폰:  POST vm/spawn      {"machine_id"}
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable

_DEFAULT_BASE = "https://labs.hackthebox.com/api/v4"


class HtbError(RuntimeError):
    """HTB 통합 오류(토큰 미설정·API 실패 등). 메시지에 토큰을 넣지 않는다."""


def _as_machine_id(value) -> int:
    """머신 ID 를 int 로 — 비정수면 HtbError(크래시 대신 호출부의 except HtbError 로 흡수)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HtbError(f"잘못된 머신 ID(정수 필요): {value!r}") from None


def clamp_difficulty(value) -> int:
    """HTB 난이도 투표는 10~100(10 단위). 범위 밖/비정수는 보정(기본 30)."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 30
    v = max(10, min(100, v))
    return (v // 10) * 10 or 10


class HtbClient:
    """HTB v4 최소 클라이언트. http 주입으로 테스트 가능(기본은 urllib)."""

    def __init__(self, token: str | None = None, base: str | None = None,
                 http: Callable[[str, dict, bytes], tuple[int, str]] | None = None):
        # 토큰은 env 에서만(인자는 테스트용). 출력·로그에 절대 노출하지 않는다.
        self.token = token if token is not None else os.environ.get("HTB_TOKEN", "")
        self.base = (base or os.environ.get("HTB_API_BASE", _DEFAULT_BASE)).rstrip("/")
        self._http = http or self._urllib_post

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())

    def _urllib_post(self, url: str, headers: dict, body: bytes) -> tuple[int, str]:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.getcode(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:   # 서버가 비2xx 응답(본문 보유) — 코드/본문 전달
            return e.code, e.read().decode("utf-8", "replace") if e.fp else str(e.reason)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # 네트워크 장애(DNS·연결실패·타임아웃) — HtbError 로 승격해 호출부의
            # except HtbError 로 흡수(run 크래시 방지). 메시지에 토큰·요청헤더 미포함.
            reason = getattr(e, "reason", None) or e
            raise HtbError(f"HTB API 네트워크 오류: {type(e).__name__}: {reason}") from None

    def _post(self, path: str, payload: dict) -> dict:
        if not self.has_token:
            raise HtbError("HTB_TOKEN 미설정 — 플래그 제출/스폰 비활성(env 로 설정 후 재시도)")
        url = f"{self.base}/{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "assassin-htb/1.0",
        }
        code, text = self._http(url, headers, json.dumps(payload).encode("utf-8"))
        if not (200 <= code < 300):
            # 본문에 토큰이 없도록 HTB 응답만 싣는다(요청 헤더는 포함 안 함).
            raise HtbError(f"HTB API {path} 실패(HTTP {code}): {text[:200]}")
        try:
            return json.loads(text) if text.strip() else {}
        except (ValueError, TypeError):
            return {"raw": text[:200]}

    def submit_flag(self, machine_id, flag: str, difficulty=30) -> dict:
        """플래그 제출 — POST machine/own. 반환: HTB 응답(dict). 토큰 없으면 HtbError."""
        if not (flag or "").strip():
            raise HtbError("빈 플래그 — 제출하지 않음")
        return self._post("machine/own", {
            "flag": flag.strip(),
            "id": _as_machine_id(machine_id),
            "difficulty": clamp_difficulty(difficulty),
        })

    def spawn_machine(self, machine_id) -> dict:
        """머신 스폰 — POST vm/spawn. 반환: HTB 응답(dict)."""
        return self._post("vm/spawn", {"machine_id": _as_machine_id(machine_id)})


def trusted_exploit_flags(report) -> set[tuple[str, str]]:
    """외부 제출(--submit-flags)의 **유일한 안전 게이트** — '공략 유래(exploit-derived)' 로
    판정된 플래그의 (kind, value) 집합만 반환. 미끼·로컬 유래(local-derived)·추론 입력
    (reasoning-only)·외부 조회(looked-up)·미검증(unverified) 유래는 전부 제외한다(§4·§3)."""
    return {(p.kind, p.value) for p in (getattr(report, "flag_provenance", []) or [])
            if getattr(p, "verdict", "") == "exploit-derived"}


# ── VPN 프리플라이트(로컬·비파괴) ───────────────────────────────────────
_HTB_RANGES = ("10.10.", "10.129.")   # HTB Labs 대역(참고). "10.10.1" 은 "10.10." 의 부분집합이라 제거(감사 A-LOW10)


def vpn_preflight(target: str, detect: Callable[[], list[str]] | None = None) -> tuple[bool, str]:
    """대상이 HTB 대역인데 VPN(tun/tap)이 안 보이면 경고(비치명적·조언). 로컬 조회만.
    detect: tun/tap IP 목록 반환 함수(기본은 environment.detect_vpn_ips) — 테스트 주입용."""
    fn = detect
    if fn is None:
        from .environment import detect_vpn_ips
        fn = detect_vpn_ips
    looks_htb = any((target or "").startswith(p) for p in _HTB_RANGES)
    vpn = fn() or []
    if not looks_htb:
        return True, ""                       # HTB 대역 아님 — 판단 보류(통과)
    if vpn:
        return True, f"VPN 활성(tun/tap: {', '.join(vpn)})"
    return False, ("HTB 대역 대상인데 VPN(tun/tap) 미탐지 — 'sudo openvpn <파일>.ovpn' 로 "
                   "연결 후 재시도 권장(도달 불가로 전 단계가 무의미할 수 있음)")
