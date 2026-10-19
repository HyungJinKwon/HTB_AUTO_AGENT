"""
Environment Preflight — Kali 런타임 사전 점검
==============================================

에이전트는 사용자의 Kali(또는 Debian계) + HTB VPN 환경에서 동작한다. 실행 전
환경을 점검해 "지금 무엇이 준비됐고 무엇이 빠졌는지"를 명확히 한다. 빠진 것을
조용히 넘기지 않는다(과장·추측 금지).
"""

from __future__ import annotations

import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field

from .tools import registry


def detect_vpn_ips() -> list[str]:
    """tun/tap 인터페이스의 IPv4(공격자 VPN IP) 탐지. 없으면 빈 목록."""
    ips: list[str] = []
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            if re.search(r"\b(?:tun|tap)\d*\b", line):
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ips.append(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ips


def _is_kali() -> bool:
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            return "kali" in f.read().lower()
    except OSError:
        return False


@dataclass
class PreflightReport:
    ok: bool
    info: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    vpn_ips: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = ["# 환경 프리플라이트"]
        lines += [f"  ✅ {i}" for i in self.info]
        lines += [f"  ⚠️ {w}" for w in self.warnings]
        lines.append(f"  VPN IP: {self.vpn_ips or '(미탐지 — HTB VPN 연결/수동지정 필요)'}")
        return "\n".join(lines)


def preflight(required_tool_keys: list[str] | None = None) -> PreflightReport:
    info, warnings = [], []

    # Python
    if sys.version_info >= (3, 10):
        info.append(f"Python {sys.version_info.major}.{sys.version_info.minor}")
    else:
        warnings.append(f"Python {sys.version_info.major}.{sys.version_info.minor} — 3.10+ 권장")

    # OS
    if platform.system() == "Linux":
        info.append("Linux" + (" (Kali)" if _is_kali() else " (Kali 아님 — 일부 apt 패키지 상이 가능)"))
    else:
        warnings.append(f"{platform.system()} — Kali/Linux 권장(도구 호환성)")

    # VPN
    vpn = detect_vpn_ips()
    if not vpn:
        warnings.append("tun/tap VPN 인터페이스 미탐지 — HTB VPN(openvpn) 연결 필요")

    # 필수 도구
    if required_tool_keys:
        ok_tools, msgs = registry.ensure_tools(required_tool_keys)
        if ok_tools:
            info.append(f"필수 도구 준비됨: {', '.join(required_tool_keys)}")
        else:
            warnings.extend(msgs)

    ok = len(warnings) == 0
    return PreflightReport(ok=ok, info=info, warnings=warnings, vpn_ips=vpn)
