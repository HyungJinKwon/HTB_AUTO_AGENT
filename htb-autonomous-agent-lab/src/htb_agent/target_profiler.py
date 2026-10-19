"""
Target Profiler — 대상 OS/역할 판정 (증거 기반)
=================================================

HTB 머신은 **Linux** 인지 **Windows(특히 Active Directory)** 인지에 따라
enumeration 경로와 도구가 완전히 갈린다. 이 모듈은 수집된 관측(열린 포트,
서비스 배너, nmap 스크립트 출력, TTL)으로부터 OS/역할을 **추측이 아니라
증거 기반**으로 판정하고, 각 판정에 **확신도(confidence)** 와 근거(evidence)를
붙인다.

원칙 (사실성·자기검증):
  - 증거가 강하면 〔확인〕, 약하면 〔추정〕 으로 태깅한다.
  - 모든 판정에 "왜 그렇게 봤는지" 근거 목록을 남긴다.
  - 결정적 신호(명시적 OS 문자열, Kerberos+LDAP 조합)를 우선한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class OSClass(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    WINDOWS_AD = "windows_ad"   # Windows + Active Directory (도메인 컨트롤러 등)
    UNKNOWN = "unknown"


# 포트 기반 신호 (서비스는 바뀔 수 있으나 조합의 설명력은 높다)
WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986, 47001}  # MSRPC, NetBIOS, SMB, RDP, WinRM
AD_PORTS = {88, 389, 636, 3268, 3269, 464}  # Kerberos, LDAP(S), Global Catalog, kpasswd
LINUX_HINT_PORTS = {22}  # SSH (약한 신호 — Windows 에도 있을 수 있음)

# 포트 → 통상 서비스명 (리포트 가독성용)
PORT_NAMES = {
    22: "SSH", 53: "DNS", 80: "HTTP", 88: "Kerberos", 135: "MSRPC",
    139: "NetBIOS-SSN", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "kpasswd",
    636: "LDAPS", 3268: "GC-LDAP", 3269: "GC-LDAPS", 3389: "RDP",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
}


@dataclass
class Evidence:
    toward: OSClass
    weight: int
    detail: str

    def __str__(self) -> str:
        sign = "+" if self.weight >= 0 else ""
        return f"[{self.toward.value} {sign}{self.weight}] {self.detail}"


@dataclass
class ProfileResult:
    os_class: OSClass
    confidence: float               # 0.0 ~ 1.0
    is_domain_controller: bool
    evidence: list[Evidence] = field(default_factory=list)
    hypotheses: list[tuple[OSClass, float]] = field(default_factory=list)

    @property
    def tag(self) -> str:
        """P4: 확신도에 따른 사실/추정 태깅."""
        return "〔확인〕" if self.confidence >= 0.85 else "〔추정〕"

    def summary(self) -> str:
        lines = [
            f"{self.tag} 판정: {self.os_class.value}"
            + (" (Domain Controller)" if self.is_domain_controller else "")
            + f"  — 확신도 {self.confidence:.0%}",
            "근거:",
        ]
        lines += [f"  · {e}" for e in self.evidence] or ["  · (근거 없음)"]
        if self.hypotheses:
            alt = ", ".join(f"{c.value} {s:.0%}" for c, s in self.hypotheses)
            lines.append(f"가설 분포: {alt}")
        return "\n".join(lines)


# 배너/스크립트 출력에서 OS 를 직접 말해 주는 강한 신호.
# 주의(감사 발견 C): "microsoft-ds" 는 nmap 이 445 포트에 붙이는 기본 라벨로
# Linux Samba 에도 나타나므로 Windows 증거가 아니다 → microsoft 뒤 '-' 제외.
# "smb-os-discovery" 는 스크립트 '이름'일 뿐(어느 OS 든 실행) → 제거.
# 'windows' 는 "for_Windows_8.1" 같은 언더스코어 결합도 잡도록 경계 완화(발견 D).
_WIN_TEXT = re.compile(r"windows|\bmicrosoft\b(?!-)", re.I)
_LIN_TEXT = re.compile(r"linux|ubuntu|debian|centos|red\s*hat|fedora|\bunix\b|freebsd", re.I)
_OPENSSH = re.compile(r"openssh", re.I)


def classify(
    open_ports,
    banners: dict[int, str] | None = None,
    script_output: str | None = None,
    ttl: int | None = None,
) -> ProfileResult:
    """
    증거를 모아 OS/역할을 판정한다.

    Parameters
    ----------
    open_ports : Iterable[int]  열린 포트 목록
    banners    : {포트: 배너문자열}  (예: {22: "OpenSSH 8.2p1 Ubuntu"})
    script_output : nmap 스크립트 출력 등 자유 텍스트 (예: smb-os-discovery 결과)
    ttl        : 관측된 TTL (약한 신호)
    """
    ports = set(int(p) for p in open_ports)
    banners = banners or {}
    text = " ".join(str(v) for v in banners.values()) + " " + (script_output or "")
    text_norm = text.strip()

    evidence: list[Evidence] = []
    win = 0
    lin = 0
    strong_win = False
    strong_lin = False

    # 1) 명시적 OS 문자열 — 가장 강한 신호
    if _WIN_TEXT.search(text_norm):
        win += 5
        strong_win = True
        evidence.append(Evidence(OSClass.WINDOWS, 5, "배너/스크립트에 Windows/Microsoft 문자열"))
    if _LIN_TEXT.search(text_norm):
        lin += 5
        strong_lin = True
        evidence.append(Evidence(OSClass.LINUX, 5, "배너/스크립트에 Linux/Unix 배포판 문자열"))
    # OpenSSH 는 보통 Linux (단, 배너가 Windows 를 명시하면 가점 안 함)
    if _OPENSSH.search(text_norm) and not _WIN_TEXT.search(text_norm):
        lin += 1
        evidence.append(Evidence(OSClass.LINUX, 1, "OpenSSH 배너 (통상 Linux)"))

    # 2) 포트 조합
    win_hit = sorted(ports & WINDOWS_PORTS)
    if win_hit:
        win += 2 * len(win_hit)
        names = ", ".join(f"{p}/{PORT_NAMES.get(p, '?')}" for p in win_hit)
        evidence.append(Evidence(OSClass.WINDOWS, 2 * len(win_hit), f"Windows 계열 포트: {names}"))
    ad_hit = sorted(ports & AD_PORTS)
    if ad_hit:
        win += 2 * len(ad_hit)  # AD 포트는 Windows 를 강하게 시사
        names = ", ".join(f"{p}/{PORT_NAMES.get(p, '?')}" for p in ad_hit)
        evidence.append(Evidence(OSClass.WINDOWS, 2 * len(ad_hit), f"AD 관련 포트: {names}"))
    if ports & LINUX_HINT_PORTS:
        lin += 1
        evidence.append(Evidence(OSClass.LINUX, 1, "SSH(22) 열림 (약한 Linux 신호)"))

    # 3) TTL (약한 신호)
    if ttl is not None:
        if 60 <= ttl <= 64:
            lin += 1
            evidence.append(Evidence(OSClass.LINUX, 1, f"TTL={ttl} (Linux 계열 ~64)"))
        elif 120 <= ttl <= 128:
            win += 1
            evidence.append(Evidence(OSClass.WINDOWS, 1, f"TTL={ttl} (Windows 계열 ~128)"))

    total = win + lin
    if total == 0:
        return ProfileResult(OSClass.UNKNOWN, 0.0, False, evidence,
                             [(OSClass.UNKNOWN, 1.0)])

    # 승자 및 확신도
    if win > lin:
        winner = OSClass.WINDOWS
    elif lin > win:
        winner = OSClass.LINUX
    else:
        # 동점 — 결정 불가, 보수적으로 UNKNOWN
        return ProfileResult(
            OSClass.UNKNOWN, 0.5, False, evidence,
            [(OSClass.WINDOWS, win / total), (OSClass.LINUX, lin / total)],
        )

    margin = abs(win - lin) / total
    confidence = 0.5 + 0.5 * margin  # 0.5 ~ 1.0
    strong_for_winner = (winner == OSClass.WINDOWS and strong_win) or \
                        (winner == OSClass.LINUX and strong_lin)
    if strong_for_winner:
        confidence = max(confidence, 0.9)
    else:
        # 감사 발견 B: 명시적 OS 문자열/AD 구조 신호가 없으면 포트만으로
        # 100% 단정하지 않는다. 0.8 로 상한 → 〔추정〕 으로 표기된다.
        confidence = min(confidence, 0.8)

    is_dc = False
    os_class = winner
    if winner == OSClass.WINDOWS:
        # AD 판정: Kerberos(88) + LDAP(389) = 도메인 컨트롤러로 강하게 시사
        if 88 in ports and 389 in ports:
            os_class = OSClass.WINDOWS_AD
            is_dc = True
            confidence = max(confidence, 0.92)
            evidence.append(Evidence(OSClass.WINDOWS_AD, 3,
                                     "Kerberos(88)+LDAP(389) → Active Directory DC"))
        elif ports & AD_PORTS:
            os_class = OSClass.WINDOWS_AD
            is_dc = 88 in ports
            confidence = max(confidence, 0.78)  # 단서 일부 → 추정
            evidence.append(Evidence(OSClass.WINDOWS_AD, 1,
                                     "일부 AD 포트 존재 → AD 가능성(추정)"))

    hypotheses = sorted(
        [(OSClass.WINDOWS, win / total), (OSClass.LINUX, lin / total)],
        key=lambda x: x[1], reverse=True,
    )
    return ProfileResult(os_class, round(confidence, 3), is_dc, evidence, hypotheses)
