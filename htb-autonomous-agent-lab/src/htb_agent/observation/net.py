"""
Network Enum Parsers — dig(DNS) / snmpwalk(SNMP) 출력 구조화
============================================================

DNS 레코드(존 트랜스퍼 포함)와 SNMP OID 값을 구조화한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── DNS (dig) ────────────────────────────────────────────────────────
@dataclass
class DnsRecord:
    name: str
    rtype: str
    value: str

    def __str__(self) -> str:
        return f"{self.name} {self.rtype} {self.value}"


@dataclass
class DnsResult:
    records: list[DnsRecord] = field(default_factory=list)
    parse_error: str = ""

    def summary(self, top: int = 12) -> str:
        if not self.records:
            return "dns: 레코드 없음" + (f" ({self.parse_error})" if self.parse_error else "")
        shown = "; ".join(str(r) for r in self.records[:top])
        more = f" …(+{len(self.records) - top})" if len(self.records) > top else ""
        return f"dns: {len(self.records)}건 — {shown}{more}"


_DIG_REC = re.compile(
    r"^(?P<name>\S+?)\.?\s+\d+\s+IN\s+"
    r"(?P<type>A|AAAA|MX|NS|TXT|CNAME|PTR|SOA|SRV|HINFO)\s+(?P<value>.+)$"
)


def parse_dig(text: str) -> DnsResult:
    res = DnsResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        m = _DIG_REC.match(line)
        if m:
            res.records.append(DnsRecord(m.group("name"), m.group("type"),
                                         m.group("value").strip()))
    return res


# ── SNMP (snmpwalk) ──────────────────────────────────────────────────
@dataclass
class SnmpResult:
    entries: list[tuple[str, str]] = field(default_factory=list)   # (oid, value)
    sysdescr: str = ""
    parse_error: str = ""

    def summary(self, top: int = 10) -> str:
        if not self.entries:
            return "snmp: 항목 없음" + (f" ({self.parse_error})" if self.parse_error else "")
        parts = []
        if self.sysdescr:
            parts.append(f"sysDescr={self.sysdescr}")
        parts.append(f"{len(self.entries)}개 OID")
        sample = "; ".join(f"{o}={v}" for o, v in self.entries[:top])
        return "snmp: " + " | ".join(parts) + (f" — {sample}" if sample else "")


_SNMP = re.compile(r"^(?P<oid>\S+)\s*=\s*(?:(?P<type>[A-Za-z0-9\-]+):\s*)?(?P<value>.+)$")


def parse_snmpwalk(text: str) -> SnmpResult:
    res = SnmpResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _SNMP.match(line)
        if not m:
            continue
        oid = m.group("oid")
        value = m.group("value").strip().strip('"')
        res.entries.append((oid, value))
        if "sysDescr" in oid or oid.endswith("1.3.6.1.2.1.1.1.0"):
            res.sysdescr = value
    return res
