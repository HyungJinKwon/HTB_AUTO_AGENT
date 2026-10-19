"""Bounded 1-day metadata research; results are leads, never proof or executable code."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .audit import NullAudit

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_FORBIDDEN = re.compile(r"\b(?:htb|writeup|walkthrough|solution)\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)


def service_query(product: str, version: str) -> str | None:
    """Only observed product/version; no target names, IPs, shell or option syntax."""
    query = f"{product} {version}".strip()
    if not product.strip() or len(query) > 100 or _FORBIDDEN.search(query):
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+()/:-]*", query):
        return None
    if any(word.startswith("-") for word in query.split()):
        return None
    return query


class OneDayResearch:
    def __init__(self, *, online: bool = False, max_queries: int = 8,
                 run=None, fetch=None, available=None, audit=None):
        self.online = online
        self.max_queries = max_queries
        self.run = run or subprocess.run
        self.fetch = fetch or self._fetch_nvd
        self.available = available or (lambda: shutil.which("searchsploit") is not None)
        self.audit = audit or NullAudit()
        self.seen: set[str] = set()
        self.results: list[dict] = []
        self.warnings: list[str] = []

    @staticmethod
    def _fetch_nvd(query: str) -> dict:
        params = {"resultsPerPage": "5"}
        params["cveId" if _CVE.fullmatch(query) else "keywordSearch"] = query
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
        req = Request(url, headers={"User-Agent": "htb-agent-lab/1.1"})
        with urlopen(req, timeout=8) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("NVD response size exceeded")
        return json.loads(raw)

    def collect(self, host, cves: list[str] | None = None) -> list[dict]:
        queries = [c.upper() for c in (cves or []) if _CVE.fullmatch(c)]
        queries += [q for p in host.ports if p.state == "open"
                    if (q := service_query(p.product, p.version))]
        for query in dict.fromkeys(queries):
            if query in self.seen or len(self.seen) >= self.max_queries:
                continue
            self.seen.add(query)
            if self.available():
                argv = ["searchsploit", "--json"]
                argv += ["--cve", query[4:]] if _CVE.fullmatch(query) else query.split()
                try:
                    output = self.run(argv, capture_output=True, text=True, timeout=8)
                    if output.returncode:
                        raise ValueError("SearchSploit returned an error")
                    if len(output.stdout) > 1_000_000:
                        raise ValueError("SearchSploit response size exceeded")
                    data = json.loads(output.stdout)
                    if not isinstance(data, dict):
                        raise ValueError("invalid SearchSploit response")
                    for item in data.get("RESULTS_EXPLOIT", [])[:5]:
                        eid = str(item.get("EDB-ID", ""))
                        if not eid.isdigit():
                            continue
                        self._add(query, "searchsploit", eid, item.get("Title", ""),
                                  "https://www.exploit-db.com/exploits/" + eid)
                    self.audit.event("research_query", source="searchsploit", query=query,
                                     status="ok")
                except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
                    self._warn("searchsploit", query)
            elif "SearchSploit 미설치" not in self.warnings:
                self.warnings.append("SearchSploit 미설치")
            # Without an API key NVD allows few requests; only one online query per run.
            if self.online and not getattr(self, "_online_used", False):
                self._online_used = True
                try:
                    data = self.fetch(query)
                    for item in data.get("vulnerabilities", [])[:5]:
                        cve = item.get("cve", {})
                        cid = str(cve.get("id", ""))
                        if not _CVE.fullmatch(cid) or cve.get("vulnStatus") == "Rejected":
                            continue
                        title = next((d.get("value", "") for d in cve.get("descriptions", [])
                                      if d.get("lang") == "en"), "")
                        self._add(query, "nvd", cid, title, "https://nvd.nist.gov/vuln/detail/" + cid)
                    self.audit.event("research_query", source="nvd", query=query, status="ok")
                except (OSError, ValueError, TypeError, AttributeError):
                    self._warn("nvd", query)
        return self.results

    def _add(self, query: str, source: str, identifier: str, title: str, url: str) -> None:
        self.results.append({"query": query, "source": source, "id": identifier,
                             "title": " ".join(str(title).split())[:180], "url": url,
                             "status": "unverified-lead"})

    def _warn(self, source: str, query: str) -> None:
        self.warnings.append(f"{source}: 조회 실패 ({query})")
        self.audit.event("research_query", source=source, query=query, status="failed")

    def context_lines(self) -> list[str]:
        return [f"UNVERIFIED {r['id']} [{r['query']}]: {r['title']} ({r['url']})"
                for r in self.results[:10]]
