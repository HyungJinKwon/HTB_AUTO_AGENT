"""
Observation Parsers — 도구 출력 구조화 파싱
=============================================

nmap / curl 출력을 **통째로 긁지 않고** 파싱해 구조화한다. 정확한 구조화가
되어야 (1) TargetProfiler 가 정확히 판정하고, (2) "host down → -Pn" 같은
폴백 전략을 정확히 결정하며, (3) LLM 에 넘길 때 토큰을 절감한다.

파싱 원칙:
  - nmap 은 **XML(-oX -)** 을 1순위로 파싱(가장 정확). 텍스트 출력도 보조 파싱.
  - "호스트가 다운으로 보임 / 핑 차단" 신호를 명시적으로 추출 → 폴백 판단 근거.
  - 실패 시 조용히 깨지지 않고 빈 결과 + 사유를 남긴다(fail-closed, 과장 금지).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


# ── nmap 구조 ────────────────────────────────────────────────────────
@dataclass
class Port:
    port: int
    proto: str
    state: str                      # open / closed / filtered ...
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)  # {script-id: output}

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extrainfo) if x)

    def __str__(self) -> str:
        svc = self.service or "?"
        b = self.banner
        return f"{self.port}/{self.proto} {self.state} {svc}" + (f" ({b})" if b else "")


@dataclass
class NmapHost:
    address: str = ""
    state: str = "unknown"          # up / down / unknown
    reason: str = ""
    ports: list[Port] = field(default_factory=list)
    hostscripts: dict[str, str] = field(default_factory=dict)
    os_guesses: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.state == "open"]

    def to_profile_inputs(self) -> dict:
        """TargetProfiler.classify() 인자로 변환."""
        banners = {p.port: p.banner for p in self.ports if p.state == "open" and p.banner}
        script_text = " ".join(self.hostscripts.values())
        for p in self.ports:
            script_text += " " + " ".join(p.scripts.values())
        return {
            "open_ports": self.open_ports,
            "banners": banners,
            "script_output": script_text.strip(),
        }


@dataclass
class NmapResult:
    hosts: list[NmapHost] = field(default_factory=list)
    parse_error: str = ""
    # 폴백 판단 신호
    any_up: bool = False
    seems_down: bool = False        # 핑 차단으로 다운처럼 보임 → -Pn 권장

    def first_host(self) -> NmapHost | None:
        return self.hosts[0] if self.hosts else None


# nmap 텍스트 출력에서 "다운처럼 보임" 힌트
_DOWN_HINT = re.compile(r"host seems down|0 hosts up|Note: Host seems down", re.I)
_PORT_LINE = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(\w+)\s+(\S+)?\s*(.*)$", re.I
)


def parse_nmap_xml(xml_text: str) -> NmapResult:
    """nmap -oX 출력(XML)을 파싱. 가장 정확한 경로."""
    result = NmapResult()
    if not xml_text or not xml_text.strip():
        result.parse_error = "빈 XML"
        return result
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        result.parse_error = f"XML 파싱 실패: {e}"
        return result

    for host_el in root.findall("host"):
        host = NmapHost()
        st = host_el.find("status")
        if st is not None:
            host.state = st.get("state", "unknown")
            host.reason = st.get("reason", "")
        addr = host_el.find("address")
        if addr is not None:
            host.address = addr.get("addr", "")

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                p = Port(
                    port=int(port_el.get("portid", "0")),
                    proto=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", "") if state_el is not None else "",
                    service=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product", "") if svc_el is not None else "",
                    version=svc_el.get("version", "") if svc_el is not None else "",
                    extrainfo=svc_el.get("extrainfo", "") if svc_el is not None else "",
                )
                for s in port_el.findall("script"):
                    p.scripts[s.get("id", "?")] = s.get("output", "")
                host.ports.append(p)

        hs = host_el.find("hostscript")
        if hs is not None:
            for s in hs.findall("script"):
                host.hostscripts[s.get("id", "?")] = s.get("output", "")

        os_el = host_el.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                name = m.get("name")
                if name:
                    host.os_guesses.append(name)

        result.hosts.append(host)

    result.any_up = any(h.state == "up" for h in result.hosts)
    if not result.any_up and result.hosts:
        result.seems_down = True
    return result


def parse_nmap_text(text: str) -> NmapResult:
    """nmap 일반(텍스트) 출력 보조 파싱. XML 이 없을 때."""
    result = NmapResult()
    if not text or not text.strip():
        result.parse_error = "빈 텍스트"
        return result
    host = NmapHost()
    m = re.search(r"Nmap scan report for\s+(\S+)", text)
    if m:
        host.address = m.group(1)
        host.state = "up"
    if _DOWN_HINT.search(text):
        result.seems_down = True
        host.state = "down"
    for line in text.splitlines():
        line = line.strip()
        pm = _PORT_LINE.match(line)
        if pm:
            port, proto, state, service, rest = pm.groups()
            host.ports.append(Port(
                port=int(port), proto=proto.lower(), state=state.lower(),
                service=(service or "").lower(), product=(rest or "").strip(),
            ))
    if host.address or host.ports:
        result.hosts.append(host)
    result.any_up = any(h.state == "up" for h in result.hosts)
    return result


# ── HTTP(curl) 구조 ──────────────────────────────────────────────────
@dataclass
class HttpResult:
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    parse_error: str = ""

    @property
    def server(self) -> str:
        return self.headers.get("server", "")

    @property
    def location(self) -> str:
        return self.headers.get("location", "")

    def summary(self) -> str:
        bits = [f"HTTP {self.status} {self.reason}".strip()]
        if self.server:
            bits.append(f"Server={self.server}")
        if self.location:
            bits.append(f"→ {self.location}")
        if self.title:
            bits.append(f'title="{self.title}"')
        for k in ("x-powered-by", "www-authenticate", "set-cookie"):
            if k in self.headers:
                bits.append(f"{k}={self.headers[k]}")
        return " | ".join(bits)


_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)$", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def parse_http(raw: str) -> HttpResult:
    """`curl -i` 스타일 출력(헤더 + 본문)을 파싱."""
    res = HttpResult()
    if not raw or not raw.strip():
        res.parse_error = "빈 응답"
        return res
    # curl -iL 은 리다이렉트 체인마다 헤더 블록이 반복된다. 빈 줄로 블록을 나눠
    # HTTP 상태줄로 시작하는 블록은 모두 헤더로 보고, 최종 응답 헤더만 남긴다.
    # 상태블록이 아닌 첫 블록(이미 상태를 본 뒤)이 본문이다.
    segments = re.split(r"\r?\n\r?\n", raw)
    body = ""
    seen_status = False
    for idx, seg in enumerate(segments):
        stripped = seg.strip()
        first = stripped.splitlines()[0] if stripped else ""
        if _STATUS_RE.match(first):
            lines = seg.splitlines()
            sm = _STATUS_RE.match(lines[0].strip())
            res.status = int(sm.group(1))
            res.reason = sm.group(2).strip()
            res.headers = {}  # 새 응답 시작 → 헤더 리셋
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    res.headers[k.strip().lower()] = v.strip()
            seen_status = True
        elif seen_status:
            body = "\r\n\r\n".join(segments[idx:])
            break

    tm = _TITLE_RE.search(body)
    if tm:
        res.title = re.sub(r"\s+", " ", tm.group(1)).strip()
    return res
