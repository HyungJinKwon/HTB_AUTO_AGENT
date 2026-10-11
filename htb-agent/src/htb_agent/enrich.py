"""
Enrich — CVE/CWE 레퍼런스 자동 수집(공식 출처만)
================================================

탐지된 CVE/CWE 에 대해 **공식 취약점 레퍼런스 데이터**를 자동으로 가져온다.
라이트업(공략) 검색이 아니라 권위 있는 취약점 DB 이므로 P1(외부 라이트업 미참조)과
충돌하지 않는다.

출처(허용 목록):
  - NVD  : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...  (CVE 설명·CVSS·참조)
  - GitHub: https://api.github.com/search/repositories?q=CVE-...            (공개 PoC 리포)
  - CWE  : 번들 테이블(대표 약점명) + (선택) MITRE 참조 링크

설계:
  - **주입식 fetcher**(fetch_fn) — 네트워크 호출을 분리해 오프라인/테스트 안전. 기본은
    urllib(표준 라이브러리) + 프록시/타임아웃. 실패 시 None → 절대 예외로 중단하지 않음.
  - **캐시** — <cache_dir>/CVE-xxxx.json 에 저장, 재실행 시 재수집 안 함(비용·속도).
  - **오프라인/비활성** — enabled=False 또는 네트워크 불가 시 캐시만 사용, 없으면 빈 결과.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Callable

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# 대표 CWE 이름(오프라인 기본 — 네트워크 없이도 분류 가능). 필요 시 확장.
CWE_NAMES: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-98": "PHP Remote File Inclusion",
    "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path or Channel",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element (DLL/SO Hijack)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-865": "Missing Privilege Check",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
}


@dataclass
class CveInfo:
    id: str
    description: str = ""
    cvss: str = ""
    severity: str = ""
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    poc_repos: list[str] = field(default_factory=list)
    source: str = "nvd"


def _default_fetcher(timeout: int = 6) -> Callable[[str], str | None]:
    """urllib 기반 GET(프록시 env 존중, 실패 시 None). 네트워크 분리 지점 — 공용 util.http_get_text."""
    from .util import http_get_text
    return lambda url: http_get_text(url, timeout=timeout, user_agent="assassin-enrich/1.0")


class Enricher:
    def __init__(self, cache_dir: str = "knowledge/cve_cache",
                 fetch_fn: Callable[[str], str | None] | None = None,
                 enabled: bool = True, want_poc: bool = True, timeout: int = 6):
        self.cache_dir = cache_dir
        self.enabled = enabled
        self.want_poc = want_poc
        self.fetch = fetch_fn or _default_fetcher(timeout)

    # ── 캐시 ────────────────────────────────────────────────────────
    def _cache_path(self, cve_id: str) -> str:
        return os.path.join(self.cache_dir, f"{cve_id.upper()}.json")

    def _load_cache(self, cve_id: str) -> CveInfo | None:
        try:
            with open(self._cache_path(cve_id), encoding="utf-8") as f:
                return CveInfo(**json.load(f))
        except (OSError, json.JSONDecodeError, TypeError):
            return None

    def _save_cache(self, info: CveInfo) -> None:
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(self._cache_path(info.id), "w", encoding="utf-8") as f:
                json.dump(asdict(info), f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ── CVE ─────────────────────────────────────────────────────────
    def enrich_cve(self, cve_id: str) -> CveInfo | None:
        cve_id = cve_id.upper()
        if not _CVE_RE.fullmatch(cve_id):
            return None
        cached = self._load_cache(cve_id)
        if cached is not None:
            return cached
        if not self.enabled:
            return None
        info = self._fetch_nvd(cve_id)
        if info is None:
            return None
        if self.want_poc:
            info.poc_repos = self._fetch_github_poc(cve_id)
        self._save_cache(info)
        return info

    def _fetch_nvd(self, cve_id: str) -> CveInfo | None:
        raw = self.fetch(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                return None
            cve = vulns[0]["cve"]
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            cvss, sev = self._parse_cvss(cve.get("metrics", {}))
            cwes = []
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwes.append(d["value"])
            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
            return CveInfo(id=cve_id, description=desc, cvss=cvss, severity=sev,
                           cwe=sorted(set(cwes)), references=refs[:8], source="nvd")
        except (json.JSONDecodeError, KeyError, TypeError, IndexError):
            return None

    @staticmethod
    def _parse_cvss(metrics: dict) -> tuple[str, str]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                d = arr[0].get("cvssData", {})
                score = d.get("baseScore", "")
                sev = (arr[0].get("baseSeverity") or d.get("baseSeverity") or "")
                return (str(score), str(sev))
        return ("", "")

    def _fetch_github_poc(self, cve_id: str) -> list[str]:
        raw = self.fetch(
            f"https://api.github.com/search/repositories?q={cve_id}&sort=stars&per_page=5")
        if not raw:
            return []
        try:
            items = json.loads(raw).get("items", [])
            return [it["html_url"] for it in items if it.get("html_url")][:5]
        except (json.JSONDecodeError, KeyError, TypeError):
            return []

    # ── CWE ─────────────────────────────────────────────────────────
    @staticmethod
    def cwe_name(cwe_id: str) -> str:
        return CWE_NAMES.get(cwe_id.upper(), "")

    @staticmethod
    def cwe_url(cwe_id: str) -> str:
        num = cwe_id.upper().replace("CWE-", "")
        return f"https://cwe.mitre.org/data/definitions/{num}.html"

    @staticmethod
    def cve_url(cve_id: str) -> str:
        """사람이 보는 NVD 상세 페이지 URL(라이트업·레퍼런스용)."""
        return f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"

    # ── 일괄 ────────────────────────────────────────────────────────
    def enrich(self, cve_ids: list[str], cwe_ids: list[str] | None = None
               ) -> list[CveInfo]:
        out: list[CveInfo] = []
        for cid in dict.fromkeys(c.upper() for c in cve_ids):   # 중복 제거·순서 유지
            info = self.enrich_cve(cid)
            if info:
                out.append(info)
        return out
