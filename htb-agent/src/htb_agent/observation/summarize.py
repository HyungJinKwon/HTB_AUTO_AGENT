"""
Tool Output Summarizer — 명령 출력을 도구별 파서로 요약
=========================================================

오케스트레이터의 enum 결과를 '통째 트렁케이트'가 아니라 도구별 구조화 파서로
요약한다. 매칭되는 파서가 없거나 결과가 비면 기존 트렁케이트로 폴백한다.
"""

from __future__ import annotations

import re
from typing import Any

from ..util import binary_of
from .ad import parse_ldapsearch
from .net import parse_dig, parse_snmpwalk
from .parsers import parse_http
from .smb import parse_nxc_smb, parse_smbclient_shares, parse_smbmap
from .web import parse_feroxbuster, parse_ffuf, parse_gobuster, parse_nikto, parse_whatweb


def _truncate(stdout: str, stderr: str, limit: int = 200) -> str:
    text = " ".join((stdout or stderr or "").split())
    return (text[:limit] + "…") if len(text) > limit else text


# PoC/스크립트 출력에서 '결과 신호' 줄을 짚는 패턴 — 배너·진행로그에 묻힌 핵심 줄(드롭된 웹셸 URL,
# 성립/실패 판정, 예외)을 요약에 보존해 '배너만 보이고 결과가 날아가는' 표시 손실을 막는다.
_SIGNAL_RE = re.compile(
    r"(https?://\S+|vulnerab|webshell|web shell|backdoor|uploaded|\?cmd=|rce\b|"
    r"shell|success|succeed|\bfail|error|exception|traceback|refus|denied|"
    r"timed?\s*out|unauthor|forbidden|not\s+vulnerab|flag|HTB\{|[0-9a-f]{32})", re.I)


def _summarize_script(stdout: str, stderr: str, limit: int = 1200) -> str:
    """인터프리터로 돈 스크립트(PoC 등)의 출력 요약 — 매칭 파서가 없을 때 200자 트렁케이트가
    배너 뒤의 핵심 결과 줄(웹셸 URL·성립 판정·예외)을 날리는 문제를 막는다. '신호' 줄을 우선
    보존하고, 없으면 꼬리 몇 줄을 남긴다. (발판 URL 의 '캡처'는 요약과 무관하게 원본 raw_output
    에서 하므로 — 이 요약은 사람이 보는 표시용. 캡처 경로는 foothold._run_one_poc 참고.)"""
    text = (stdout or "") + (("\n" + stderr) if stderr else "")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return _truncate(stdout, stderr)
    signal: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        if _SIGNAL_RE.search(ln) and ln not in seen:
            signal.append(ln)
            seen.add(ln)
    picked = signal or lines[-3:]   # 신호가 하나도 없으면 마지막 몇 줄(통상 결과/판정)을 보존
    out = " · ".join(picked)
    return (out[:limit] + "…") if len(out) > limit else out


def summarize_tool_output(cmd: str, stdout: str, stderr: str = "") -> str:
    """명령/출력을 도구별로 요약. 실패 시 트렁케이트 폴백."""
    r: Any   # 도구별 파서 결과(타입이 도구마다 다름)
    binary = binary_of(cmd, strip_path=True)
    try:
        if binary == "curl" and "http" in cmd:
            h = parse_http(stdout)
            if h.status is not None:
                return h.summary()
        elif binary == "gobuster":
            r = parse_gobuster(stdout)
            if r.entries:
                return r.summary()
        elif binary == "ffuf":
            r = parse_ffuf(stdout)
            if r.entries:
                return r.summary()
        elif binary == "feroxbuster":
            r = parse_feroxbuster(stdout)
            if r.entries:
                return r.summary()
        elif binary == "nikto":
            r = parse_nikto(stdout)
            if r.server or r.findings:
                return r.summary()
        elif binary == "whatweb":
            r = parse_whatweb(stdout)
            if r.plugins:
                return r.summary()
        elif binary == "ldapsearch":
            r = parse_ldapsearch(stdout)
            if r.naming_contexts or r.dns:
                return r.summary()
        elif binary == "dig":
            r = parse_dig(stdout)
            if r.records:
                return r.summary()
        elif binary in ("snmpwalk", "snmp-check", "snmpbulkwalk"):
            r = parse_snmpwalk(stdout)
            if r.entries:
                return r.summary()
        elif binary == "smbclient" and "-L" in cmd:
            r = parse_smbclient_shares(stdout)
            if r.shares:
                return r.summary()
        elif binary == "smbmap":
            r = parse_smbmap(stdout)
            if r.shares or r.info:
                return r.summary()
        elif binary in ("nxc", "netexec", "crackmapexec", "cme"):
            r = parse_nxc_smb(stdout)
            if r.info:
                return r.summary()
        elif binary == "searchsploit":
            # 기본 200자 트렁케이트는 익스 행('제목 | 경로')을 통째로 날린다 → 전용 요약으로
            # 쌍을 보존한다(하류 _exploit_lookup_stage 가 이 요약을 재파싱해 PoC 후보를 추림).
            from ..searchsploit import parse_searchsploit
            hits = parse_searchsploit(stdout)
            if hits:
                shown = hits[:12]
                body = "; ".join(f"{h.title} | {h.locator}" for h in shown)
                more = f" …(+{len(hits) - 12})" if len(hits) > 12 else ""
                return f"searchsploit: {len(hits)}건 — {body}{more}"
        elif binary in ("python", "python3", "ruby", "php", "perl", "sh", "bash"):
            # 인터프리터로 돈 스크립트(PoC 등) — 200자 트렁케이트는 배너 뒤 결과 줄을 날린다.
            # 신호 줄(웹셸 URL·성립/실패·예외)을 보존하는 전용 요약으로 표시 손실을 막는다.
            return _summarize_script(stdout, stderr)
    except Exception:
        pass  # 파서 예외는 폴백으로 흡수(출력을 숨기지 않음)
    return _truncate(stdout, stderr)
