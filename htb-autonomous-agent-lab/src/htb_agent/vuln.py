"""
Vulnerability Mapping — CVE/CWE 탐지 및 매핑
=============================================

P1(외부 라이트업/검색 금지)을 지키며 취약점을 다룬다:
  1. 추출  : 도구 출력(nmap vuln NSE, nikto, searchsploit 등)에 '이미 나타난'
             CVE/CWE ID 를 파싱 추출(외부 조회 아님).
  2. 매핑  : '사용자 제공' 취약점 규칙(서비스+버전 → CVE/CWE)으로 관측 서비스를
             매칭. 규칙은 knowledge/vulns/*.json 으로 누적(성장).

매칭 결과는 익스플로잇 루프(`exploit_loop.py`)의 **후보 생성 컨텍스트**로 쓰인다 —
LLM 이 어떤 기존 도구(searchsploit·msfconsole·nuclei 등)를 돌릴지 고를 근거다.
실행은 루프가 검증→범위→승인 3관문(`Gate`)을 거쳐 수행하며, 범위 밖 타격과
파괴 명령은 scope_guard·command_validator 가 계속 막는다.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CWE_RE = re.compile(r"CWE-\d+", re.I)


def _version_in(version: str, text: str) -> bool:
    """버전 경계 매칭 — '2.3.4' 가 '12.3.4'/'2.3.40' 에 오매칭되지 않도록."""
    pat = r"(?<![\d.])" + re.escape(version) + r"(?![\d])"
    return re.search(pat, text) is not None


@dataclass
class VulnHits:
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)

    def any(self) -> bool:
        return bool(self.cves or self.cwes)


def extract_vuln_ids(text: str) -> VulnHits:
    """텍스트에서 CVE/CWE ID 를 추출(중복 제거·정렬)."""
    if not text:
        return VulnHits()
    cves = sorted({m.upper() for m in _CVE_RE.findall(text)})
    cwes = sorted({m.upper() for m in _CWE_RE.findall(text)})
    return VulnHits(cves, cwes)


@dataclass
class VulnRule:
    name: str
    service: str
    version_contains: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    suggest: list[str] = field(default_factory=list)
    note: str = ""
    severity: str = ""
    source: str = "builtin"


@dataclass
class VulnMatch:
    name: str
    cve: list[str]
    cwe: list[str]
    suggest: list[str]
    note: str
    severity: str
    matched_on: str
    source: str


# 내장 시드 — 일반적으로 알려진 버전↔취약점(특정 머신 라이트업 아님)
SEED_VULNS: list[VulnRule] = [
    VulnRule("vsftpd 2.3.4 백도어", "vsftpd", ["2.3.4"], ["CVE-2011-2523"], ["CWE-78"],
             ["searchsploit vsftpd 2.3.4"], "스마일리 백도어", "critical"),
    VulnRule("Apache 경로 우회/RCE", "Apache", ["2.4.49", "2.4.50"],
             ["CVE-2021-41773", "CVE-2021-42013"], ["CWE-22"],
             ["searchsploit apache 2.4.49"], "path traversal→RCE", "high"),
    VulnRule("OpenSSH 사용자 열거", "OpenSSH", ["7.2", "7.3", "7.4", "7.5", "7.6", "7.7"],
             ["CVE-2018-15473"], ["CWE-200"],
             ["searchsploit openssh username enumeration"], "유저 열거", "medium"),
    VulnRule("Samba is_known_pipename", "Samba", ["3.5", "4.0", "4.1", "4.2", "4.3", "4.4"],
             ["CVE-2017-7494"], ["CWE-94"], ["searchsploit samba is_known_pipename"],
             "RCE(쓰기가능 공유 필요)", "high"),
    VulnRule("OpenSSL Heartbleed", "OpenSSL", ["1.0.1"], ["CVE-2014-0160"], ["CWE-125"],
             ["searchsploit heartbleed"], "메모리 누출", "high"),
    VulnRule("SMBv1 EternalBlue 의심", "Windows", ["7", "2008", "2003"],
             ["CVE-2017-0144"], ["CWE-20"], ["searchsploit eternalblue"],
             "SMBv1 활성 시 점검", "critical"),
]


class VulnKB:
    def __init__(self, rules: list[VulnRule] | None = None):
        self.rules = rules if rules is not None else []

    @classmethod
    def load(cls, base_dir: str | None = None, include_seeds: bool = True) -> "VulnKB":
        rules: list[VulnRule] = list(SEED_VULNS) if include_seeds else []
        if base_dir:
            rules += _load_vuln_dir(os.path.join(base_dir, "vulns"))
        return cls(rules)

    def match(self, banners: list[str], target: str = "") -> list[VulnMatch]:
        """관측 배너 목록에 대해 취약점 규칙을 매칭."""
        out: list[VulnMatch] = []
        seen: set[str] = set()
        for rule in self.rules:
            svc = rule.service.lower()
            for banner in banners:
                bl = banner.lower()
                if svc not in bl:
                    continue
                if rule.version_contains and not any(_version_in(v.lower(), bl)
                                                     for v in rule.version_contains):
                    continue
                if rule.name in seen:
                    break
                seen.add(rule.name)
                suggest = [s.replace("{t}", target) for s in rule.suggest]
                out.append(VulnMatch(rule.name, list(rule.cve), list(rule.cwe), suggest,
                                     rule.note, rule.severity, banner, rule.source))
                break
        # severity 우선 정렬
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
        out.sort(key=lambda m: order.get(m.severity, 4))
        return out


def _load_vuln_dir(path: str) -> list[VulnRule]:
    out: list[VulnRule] = []
    if not os.path.isdir(path):
        return out
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(path, fn), encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        items = data if isinstance(data, list) else [data]
        for it in items:
            if not isinstance(it, dict) or "name" not in it or "service" not in it:
                continue
            out.append(VulnRule(
                name=str(it["name"]), service=str(it["service"]),
                version_contains=[str(v) for v in it.get("version_contains", [])],
                cve=[str(c) for c in it.get("cve", [])],
                cwe=[str(c) for c in it.get("cwe", [])],
                suggest=[str(s) for s in it.get("suggest", [])],
                note=str(it.get("note", "")), severity=str(it.get("severity", "")),
                source=f"user:{fn}",
            ))
    return out
