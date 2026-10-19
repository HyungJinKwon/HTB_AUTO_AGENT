"""
Tool Registry — 도구 목록·가용성 체크·설치 힌트
================================================

HTB 공격 체인은 대상(Linux / Windows-AD / 클라우드)에 따라 필요한 도구가
다르다. 이 레지스트리는 (1) 어떤 도구가 필요한지, (2) 현재 머신에 설치돼
있는지, (3) 없으면 어떻게 설치하는지를 한 곳에서 관리한다.

오케스트레이터는 단계 실행 '전에' 필요한 도구의 가용성을 확인하고, 없으면
그 단계를 건너뛰거나 사용자에게 설치를 안내한다(무한 재시도 금지).

주의: 실제 설치는 사용자의 Kali/Ubuntu 에서 `scripts/install_tools.sh` 로
수행한다. 이 모듈은 '확인·안내' 전용이다.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field


@dataclass
class Tool:
    key: str
    binaries: list[str]              # 설치 여부를 확인할 실행파일 후보
    category: str                    # recon/web/smb/ad/creds/cloud/pivot/wordlist
    purpose: str
    apt: list[str] = field(default_factory=list)
    pipx: list[str] = field(default_factory=list)
    go: list[str] = field(default_factory=list)
    note: str = ""

    def install_hint(self) -> str:
        parts = []
        if self.apt:
            parts.append("apt: sudo apt install -y " + " ".join(self.apt))
        if self.pipx:
            parts.append("pipx: " + "; ".join(f"pipx install {p}" for p in self.pipx))
        if self.go:
            parts.append("go: " + "; ".join(f"go install {g}" for g in self.go))
        return " | ".join(parts) or "(수동 설치)"


# 카테고리별 핵심 도구 (HTB Linux/AD/클라우드 커버)
TOOLS: list[Tool] = [
    # ── recon ──
    Tool("nmap", ["nmap"], "recon", "포트/서비스 스캔", apt=["nmap"]),
    Tool("masscan", ["masscan"], "recon", "고속 포트 스캔", apt=["masscan"]),
    Tool("rustscan", ["rustscan"], "recon", "빠른 포트 스캔", note="cargo/릴리스 바이너리"),
    Tool("autorecon", ["autorecon"], "recon", "자동 다단계 enum", pipx=["autorecon"]),
    # ── web ──
    Tool("ffuf", ["ffuf"], "web", "웹 퍼징", apt=["ffuf"]),
    Tool("gobuster", ["gobuster"], "web", "디렉토리/vhost 브루트", apt=["gobuster"]),
    Tool("feroxbuster", ["feroxbuster"], "web", "재귀 디렉토리 탐색", apt=["feroxbuster"]),
    Tool("nikto", ["nikto"], "web", "웹 취약점 스캐너", apt=["nikto"]),
    Tool("whatweb", ["whatweb"], "web", "웹 기술 식별", apt=["whatweb"]),
    Tool("curl", ["curl"], "web", "HTTP 요청", apt=["curl"]),
    # ── smb / windows ──
    Tool("smbclient", ["smbclient"], "smb", "SMB 공유 접근", apt=["smbclient"]),
    Tool("smbmap", ["smbmap"], "smb", "SMB 공유 열거", apt=["smbmap"]),
    Tool("enum4linux-ng", ["enum4linux-ng", "enum4linux-ng.py"], "smb",
         "SMB/RPC 종합 열거", pipx=["enum4linux-ng"]),
    Tool("rpcclient", ["rpcclient"], "smb", "MSRPC 질의", apt=["smbclient"]),
    # ── active directory ──
    Tool("netexec", ["nxc", "netexec", "crackmapexec", "cme"], "ad",
         "AD/SMB 스프레이·실행 (CME 후속)", pipx=["netexec"]),
    Tool("impacket", ["impacket-GetNPUsers", "GetNPUsers.py", "impacket-secretsdump"],
         "ad", "Kerberos·SMB·DCSync 스크립트 모음", pipx=["impacket"]),
    Tool("bloodhound-python", ["bloodhound-python"], "ad",
         "AD 그래프 수집(ingestor)", pipx=["bloodhound"],
         note="수집 데이터는 BloodHound GUI 로 분석"),
    Tool("bloodhound", ["bloodhound"], "ad",
         "AD 공격경로 그래프 분석 GUI", apt=["bloodhound", "neo4j"],
         note="neo4j 함께 필요. Kali 권장"),
    Tool("kerbrute", ["kerbrute"], "ad", "유저 열거/AS-REP",
         go=["github.com/ropnop/kerbrute@latest"]),
    Tool("certipy", ["certipy", "certipy-ad"], "ad", "AD CS(ESC) 공격", pipx=["certipy-ad"]),
    Tool("evil-winrm", ["evil-winrm"], "ad", "WinRM 셸", apt=["evil-winrm"]),
    Tool("sshpass", ["sshpass"], "creds", "비대화형 SSH 암호 전달(플래그 획득)", apt=["sshpass"]),
    Tool("ldapsearch", ["ldapsearch"], "ad", "LDAP 질의", apt=["ldap-utils"]),
    Tool("responder", ["responder"], "ad", "LLMNR/NBT-NS 포이즈닝", apt=["responder"]),
    # ── dns / snmp ──
    Tool("dig", ["dig"], "recon", "DNS 질의/존 트랜스퍼", apt=["dnsutils"]),
    Tool("dnsenum", ["dnsenum"], "recon", "DNS 열거", apt=["dnsenum"]),
    Tool("snmpwalk", ["snmpwalk"], "recon", "SNMP OID 수집", apt=["snmp"]),
    Tool("onesixtyone", ["onesixtyone"], "recon", "SNMP community 브루트", apt=["onesixtyone"]),
    # ── creds / cracking ──
    Tool("hydra", ["hydra"], "creds", "온라인 브루트포스", apt=["hydra"]),
    Tool("john", ["john"], "creds", "오프라인 해시 크랙", apt=["john"]),
    Tool("hashcat", ["hashcat"], "creds", "GPU 해시 크랙", apt=["hashcat"]),
    # ── cloud / S3 ──
    Tool("awscli", ["aws"], "cloud", "AWS/S3 조작", apt=["awscli"]),
    Tool("s3scanner", ["s3scanner"], "cloud", "공개 S3 버킷 열거", pipx=["s3scanner"]),
    Tool("cloud_enum", ["cloud_enum", "cloud_enum.py"], "cloud",
         "멀티클라우드(S3/GCP/Azure) 열거", pipx=["cloud-enum"]),
    # ── pivot / shell ──
    Tool("netcat", ["nc", "ncat"], "pivot", "리버스/바인드 셸", apt=["netcat-traditional"]),
    Tool("socat", ["socat"], "pivot", "소켓 릴레이", apt=["socat"]),
    Tool("chisel", ["chisel"], "pivot", "터널링", go=["github.com/jpillora/chisel@latest"]),
    # ── wordlists ──
    Tool("seclists", ["/usr/share/seclists"], "wordlist", "워드리스트 모음",
         apt=["seclists"], note="경로 존재로 확인"),
]

TOOLS_BY_KEY = {t.key: t for t in TOOLS}


def _found_binary(t: Tool) -> str | None:
    """설치돼 있으면 발견된 바이너리/경로, 아니면 None."""
    for b in t.binaries:
        if b.startswith("/"):
            import os
            if os.path.exists(b):
                return b
        elif shutil.which(b):
            return shutil.which(b)
    return None


def check_available() -> dict[str, str | None]:
    """{tool_key: 발견경로 또는 None}."""
    return {t.key: _found_binary(t) for t in TOOLS}


def missing_tools(categories: list[str] | None = None) -> list[Tool]:
    """미설치 도구 목록(선택: 특정 카테고리만)."""
    avail = check_available()
    out = []
    for t in TOOLS:
        if categories and t.category not in categories:
            continue
        if avail[t.key] is None:
            out.append(t)
    return out


def ensure_tools(keys: list[str]) -> tuple[bool, list[str]]:
    """
    주어진 도구들이 모두 설치됐는지 확인. (all_ok, 안내문 목록) 반환.
    오케스트레이터가 단계 실행 전에 호출 → 없으면 건너뛰고 안내(무한재시도 금지).
    """
    msgs: list[str] = []
    ok = True
    for k in keys:
        t = TOOLS_BY_KEY.get(k)
        if t is None:
            msgs.append(f"[미등록 도구] {k}")
            ok = False
            continue
        if _found_binary(t) is None:
            ok = False
            msgs.append(f"[미설치] {k} — {t.purpose}\n        설치: {t.install_hint()}")
    return ok, msgs


def report(categories: list[str] | None = None) -> str:
    """가용성 리포트(설치/미설치 + 설치힌트)."""
    avail = check_available()
    lines = ["# 도구 가용성 리포트"]
    cats: dict[str, list[Tool]] = {}
    for t in TOOLS:
        if categories and t.category not in categories:
            continue
        cats.setdefault(t.category, []).append(t)
    for cat, items in cats.items():
        lines.append(f"\n[{cat}]")
        for t in items:
            path = avail[t.key]
            if path:
                lines.append(f"  ✅ {t.key:16} {path}")
            else:
                lines.append(f"  ⛔ {t.key:16} 미설치 — {t.install_hint()}")
    return "\n".join(lines)
