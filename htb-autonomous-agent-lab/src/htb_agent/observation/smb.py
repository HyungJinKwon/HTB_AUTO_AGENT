"""
SMB Enum Parsers — smbclient / smbmap / netexec(nxc) 출력 구조화
================================================================

SMB 공유·권한·호스트 정보를 파싱한다. Windows/AD 대상에서 다음 단계(쓰기 가능한
공유, 널 세션, 도메인/시그닝 등) 판단 근거가 된다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Share:
    name: str
    type: str = ""
    comment: str = ""
    access: str = ""

    def __str__(self) -> str:
        bits = [self.name]
        if self.type:
            bits.append(self.type)
        if self.access:
            bits.append(self.access)
        if self.comment:
            bits.append(f'"{self.comment}"')
        return " ".join(bits)


@dataclass
class SmbResult:
    shares: list[Share] = field(default_factory=list)
    info: dict = field(default_factory=dict)      # host/os/domain/signing/name
    parse_error: str = ""

    def summary(self) -> str:
        parts = []
        if self.info:
            kv = ", ".join(f"{k}={v}" for k, v in self.info.items())
            parts.append(f"호스트[{kv}]")
        if self.shares:
            parts.append(f"공유 {len(self.shares)}건: " + "; ".join(str(s) for s in self.shares))
        if not parts:
            return "SMB: 정보 없음" + (f" ({self.parse_error})" if self.parse_error else "")
        return " | ".join(parts)


# smbclient -L:   Sharename   Type   Comment
_SMBCLIENT_SHARE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9$._\-]+)\s+(?P<type>Disk|IPC|Printer)\b\s*(?P<comment>.*)$"
)


def parse_smbclient_shares(text: str) -> SmbResult:
    res = SmbResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        if "Sharename" in raw or set(raw.strip()) <= {"-", " "}:
            continue
        m = _SMBCLIENT_SHARE.match(raw)
        if m:
            res.shares.append(Share(name=m.group("name"), type=m.group("type"),
                                    comment=m.group("comment").strip()))
    return res


# smbmap:   backups   READ ONLY   comment
_SMBMAP_PERMS = r"(NO ACCESS|READ ONLY|READ,\s*WRITE|READ, WRITE|WRITE ONLY|READ/WRITE)"
_SMBMAP_SHARE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9$._\-]+)\s+(?P<access>" + _SMBMAP_PERMS + r")\s*(?P<comment>.*)$"
)


def parse_smbmap(text: str) -> SmbResult:
    res = SmbResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    m_host = re.search(r"IP:\s*(\S+?)(?::\d+)?\s+Name:\s*(\S+)", text)
    if m_host:
        res.info["ip"] = m_host.group(1)
        res.info["name"] = m_host.group(2)
    for raw in text.splitlines():
        if "Permissions" in raw or "Disk" == raw.strip():
            continue
        m = _SMBMAP_SHARE.match(raw)
        if m:
            res.shares.append(Share(name=m.group("name"),
                                    access=re.sub(r"\s+", " ", m.group("access")),
                                    comment=m.group("comment").strip()))
    return res


# netexec/nxc:  SMB  10.129.1.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
_NXC_LINE = re.compile(r"^\s*SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<host>\S+)\s+\[\*\]\s*(?P<os>.*)$")


def parse_nxc_smb(text: str) -> SmbResult:
    res = SmbResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        m = _NXC_LINE.match(raw)
        if not m:
            continue
        res.info["ip"] = m.group("ip")
        res.info["host"] = m.group("host")
        ostext = m.group("os")
        os_main = ostext.split("(")[0].strip()
        if os_main:
            res.info["os"] = os_main
        for key in ("name", "domain", "signing", "SMBv1"):
            km = re.search(rf"\({key}:([^)]*)\)", ostext)
            if km:
                res.info[key] = km.group(1)
        break  # 첫 SMB 라인이 호스트 식별
    return res
