"""
Scope Guard — 교육용 경계 강제 모듈 (Target-Binding 모델)
=========================================================

이 에이전트는 **권한이 확인된 HTB 머신** 에 한정해서만 동작한다. Scope Guard 는
그 경계를 코드로 못 박는 핵심 안전장치다.

설계(승인제·실행전검증 원칙, 사용자 확정 "2번: 기본거부 + 승인단계 추가확인"):

  1. **Target-Binding** : 세션은 단 하나의 '타겟 IP' 에 바인딩된다. 바인딩 시
     타겟이 허용 HTB 대역 안인지 '한 번' 검증한다. 이후 모든 명령은 이 타겟을
     기준으로 판정된다. (명령 속 점4자리를 전부 타겟으로 긁던 초안의 결함 제거)

  2. **IP 분류** : 명령에 등장하는 각 IP/호스트를 아래로 분류한다.
       · TARGET    — 바인딩된 타겟          → 자동 허용
       · ATTACKER  — 공격자 VPN IP(tun0)    → 자동 허용 (리버스셸/페이로드)
       · LOOPBACK  — 127.0.0.0/8            → 자동 허용
       · UNKNOWN   — 그 외                   → '추가 확인' 대상 (기본 자동통과 거부)

  3. **호스트네임 해석** : machine.htb 같은 vhost 는 /etc/hosts 로 해석해 분류한다.
     해석된 IP 가 타겟이면 통과, 아니거나 미해석이면 추가 확인 대상.

  4. **승인 연동** : UNKNOWN 이 하나라도 있으면 auto_allowed=False → 승인 레이어가
     "이 IP/호스트는 범위 밖입니다. 그래도 실행?" 하고 명시적 재확인을 받는다.
     즉 하드 차단이 아니라 '기본 거부 + 사람이 확인하면 허용'.

  5. **Fail-closed** : 바인딩 전에는 어떤 명령도 검사/실행 대상이 아니다.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

logger = logging.getLogger("htb_agent.scope_guard")

# HTB 통상 대역 〔추정 — 통념〕. 런타임 tun0 탐지/ config 로 덮어쓸 것.
DEFAULT_HTB_RANGES: tuple[str, ...] = ("10.10.10.0/23", "10.129.0.0/16")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_HOST_RE = re.compile(r"https?://(?:[^@/\s]+@)?([A-Za-z0-9.\-]+)", re.I)
_HOSTLIKE_RE = re.compile(r"^[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+$")
# 호스트로 오인하기 쉬운 파일 확장자(점 포함 토큰) 제외 → 오탐 방지
_NONHOST_EXT = {
    "nse", "txt", "sh", "py", "html", "htm", "php", "xml", "json", "yaml", "yml",
    "conf", "cfg", "log", "md", "js", "css", "asp", "aspx", "jsp", "bak", "zip",
    "tar", "gz", "csv", "pdf", "png", "jpg", "exe", "dll", "so",
}


class ScopeViolation(Exception):
    """허용 범위를 벗어났거나 전제(바인딩)가 깨졌을 때 발생."""


class IPClass(str, Enum):
    TARGET = "target"
    ATTACKER = "attacker"
    LOOPBACK = "loopback"
    UNKNOWN = "unknown"


@dataclass
class CommandScopeResult:
    command: str
    classified: list[tuple[str, IPClass, str]] = field(default_factory=list)
    needs_confirmation: list[str] = field(default_factory=list)

    @property
    def auto_allowed(self) -> bool:
        """추가확인 대상이 없으면 (타겟/공격자/loopback 뿐) 자동 허용."""
        return not self.needs_confirmation

    def summary(self) -> str:
        head = "✅ 범위내(자동허용)" if self.auto_allowed else "⚠️ 추가확인 필요"
        lines = [f"{head} — $ {self.command}"]
        for tok, cls, note in self.classified:
            lines.append(f"  · {tok} → {cls.value}" + (f" {note}" if note else ""))
        if self.needs_confirmation:
            lines.append(f"  ⚠️ 범위 밖/미해석: {self.needs_confirmation}")
        if not self.classified:
            lines.append("  · (네트워크 대상 없음 — 로컬 명령)")
        return "\n".join(lines)


@dataclass
class ScopeGuard:
    allowed_target_cidrs: list[ipaddress.IPv4Network] = field(default_factory=list)
    bound_target: ipaddress.IPv4Address | None = None
    attacker_ips: set[ipaddress.IPv4Address] = field(default_factory=set)

    # ── 생성 ────────────────────────────────────────────────────────
    @classmethod
    def from_cidr_strings(cls, cidrs: Iterable[str] | None = None) -> "ScopeGuard":
        raw = list(cidrs) if cidrs else list(DEFAULT_HTB_RANGES)
        nets: list[ipaddress.IPv4Network] = []
        for c in raw:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError as exc:
                raise ValueError(f"잘못된 CIDR 설정: {c!r} ({exc})") from exc
        if not nets:
            raise ValueError("Scope Guard: 허용 대역이 비어 있습니다. fail-closed.")
        logger.info("Scope Guard — 허용 타겟 대역: %s", [str(n) for n in nets])
        return cls(allowed_target_cidrs=nets)

    # ── 타겟 바인딩 ─────────────────────────────────────────────────
    def bind_target(self, ip: str) -> ipaddress.IPv4Address:
        """타겟을 허용 대역에 대해 검증하고 세션에 바인딩한다."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise ScopeViolation(f"타겟 IP 파싱 실패: {ip!r}") from exc
        if isinstance(addr, ipaddress.IPv6Address):
            raise ScopeViolation("현재 IPv4 타겟만 지원합니다(IPv6 미지원).")
        if not any(addr in net for net in self.allowed_target_cidrs):
            raise ScopeViolation(
                f"타겟 {addr} 은(는) 허용 HTB 대역({self.describe()}) 밖입니다. 바인딩 거부."
            )
        self.bound_target = addr
        logger.info("타겟 바인딩: %s", addr)
        return addr

    def add_attacker_ip(self, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise ValueError(f"공격자 IP 파싱 실패: {ip!r}") from exc
        self.attacker_ips.add(addr)
        logger.info("공격자 VPN IP 등록: %s", addr)

    def detect_attacker_ips(self) -> list[str]:
        """
        tun/tap 인터페이스에서 공격자 VPN IP 를 best-effort 로 탐지해 등록.
        (이 클라우드 컨테이너엔 `ip` 명령/인터페이스가 없어 no-op. 실제 Kali 용.)
        """
        found: list[str] = []
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                                 capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                if re.search(r"\b(?:tun|tap)\d*\b", line):
                    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        self.add_attacker_ip(m.group(1))
                        found.append(m.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("공격자 IP 자동탐지 불가(%s) — 수동 등록 필요.", exc)
        return found

    # ── 분류 ────────────────────────────────────────────────────────
    def classify_ip(self, ip: str) -> IPClass:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return IPClass.UNKNOWN
        if self.bound_target is not None and addr == self.bound_target:
            return IPClass.TARGET
        if addr in self.attacker_ips:
            return IPClass.ATTACKER
        if addr.is_loopback:
            return IPClass.LOOPBACK
        return IPClass.UNKNOWN

    # ── 명령 검사 ───────────────────────────────────────────────────
    def inspect_command(self, command: str,
                        hosts_map: dict[str, str] | None = None) -> CommandScopeResult:
        """명령 속 IP/호스트를 분류한다. 바인딩 전에는 fail-closed."""
        if self.bound_target is None:
            raise ScopeViolation("타겟이 바인딩되지 않았습니다. bind_target() 먼저 호출하세요.")
        hosts_map = hosts_map if hosts_map is not None else self.load_etc_hosts()
        result = CommandScopeResult(command=command)

        for ip in _IPV4_RE.findall(command):
            cls = self.classify_ip(ip)
            result.classified.append((ip, cls, ""))
            if cls == IPClass.UNKNOWN:
                result.needs_confirmation.append(ip)

        for host in self._extract_hosts(command):
            resolved = hosts_map.get(host.lower())
            if resolved:
                cls = self.classify_ip(resolved)
                result.classified.append((host, cls, f"→{resolved}"))
                if cls == IPClass.UNKNOWN:
                    result.needs_confirmation.append(f"{host}({resolved})")
            else:
                if host.endswith(".htb") or host.endswith(".local"):
                    note = "미해석(/etc/hosts에 추가 필요)"
                    result.needs_confirmation.append(f"{host}(미해석)")
                else:
                    note = "외부도메인(미해석)"
                    result.needs_confirmation.append(f"{host}(외부)")
                result.classified.append((host, IPClass.UNKNOWN, note))

        return result

    # ── 보조 ────────────────────────────────────────────────────────
    @staticmethod
    def _extract_hosts(command: str) -> set[str]:
        hosts: set[str] = set()
        for m in _URL_HOST_RE.finditer(command):
            h = m.group(1).lower()
            if _IPV4_RE.fullmatch(h):
                continue  # IP 리터럴은 IP 경로가 처리 → 호스트로 중복 포착 금지
            hosts.add(h)
        for tok in re.split(r"[\s=,'\"|;()<>]+", command):
            t = tok.strip().lower()
            if not t or "/" in t:
                continue
            if _IPV4_RE.fullmatch(t):
                continue
            if not _HOSTLIKE_RE.fullmatch(t):
                continue
            if not re.search(r"[A-Za-z]", t):
                continue
            if t.rsplit(".", 1)[-1] in _NONHOST_EXT:
                continue
            hosts.add(t)
        return hosts

    @staticmethod
    def load_etc_hosts(path: str = "/etc/hosts") -> dict[str, str]:
        """/etc/hosts 를 {호스트명(lower): IP} 로 읽는다(HTB vhost 워크플로)."""
        mapping: dict[str, str] = {}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    ip = parts[0]
                    if not _IPV4_RE.fullmatch(ip):
                        continue
                    for name in parts[1:]:
                        mapping.setdefault(name.lower(), ip)
        except OSError:
            pass
        return mapping

    def describe(self) -> str:
        return ", ".join(str(n) for n in self.allowed_target_cidrs)
