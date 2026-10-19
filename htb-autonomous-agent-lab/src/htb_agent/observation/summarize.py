"""
Tool Output Summarizer — 명령 출력을 도구별 파서로 요약
=========================================================

오케스트레이터의 enum 결과를 '통째 트렁케이트'가 아니라 도구별 구조화 파서로
요약한다. 매칭되는 파서가 없거나 결과가 비면 기존 트렁케이트로 폴백한다.
"""

from __future__ import annotations

from ..util import binary_of
from .parsers import parse_http
from .web import (parse_gobuster, parse_ffuf, parse_feroxbuster,
                  parse_nikto, parse_whatweb)
from .smb import parse_smbclient_shares, parse_smbmap, parse_nxc_smb
from .ad import parse_ldapsearch
from .net import parse_dig, parse_snmpwalk


def _truncate(stdout: str, stderr: str, limit: int = 200) -> str:
    text = " ".join((stdout or stderr or "").split())
    return (text[:limit] + "…") if len(text) > limit else text


def summarize_tool_output(cmd: str, stdout: str, stderr: str = "") -> str:
    """명령/출력을 도구별로 요약. 실패 시 트렁케이트 폴백."""
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
    except Exception:
        pass  # 파서 예외는 폴백으로 흡수(출력을 숨기지 않음)
    return _truncate(stdout, stderr)
