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
                try:
                    portid = int(port_el.get("portid", "0"))
                except (TypeError, ValueError):
                    # 잘 구성됐으나 portid 가 빈/비정수인 비정상 XML — fail-closed 계약대로
                    # 크래시 대신 그 포트만 건너뛴다(실 nmap -oX 는 항상 정수 portid).
                    continue
                p = Port(
                    port=portid,
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
# 보안 헤더(있으면 방어↑, 없으면 블루팀 점검 포인트). {헤더(lower): 표기}
SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


@dataclass
class Cookie:
    name: str
    httponly: bool = False
    secure: bool = False
    samesite: str = ""

    def __str__(self) -> str:
        flags = []
        if self.httponly:
            flags.append("HttpOnly")
        if self.secure:
            flags.append("Secure")
        if self.samesite:
            flags.append(f"SameSite={self.samesite}")
        missing = [f for f in ("HttpOnly", "Secure") if f not in flags]
        tail = f" [{','.join(flags)}]" if flags else ""
        tail += f" (취약: {','.join('No'+m for m in missing)})" if missing else ""
        return self.name + tail


@dataclass
class HttpForm:
    action: str = ""
    method: str = "get"
    has_password: bool = False
    inputs: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        kind = "로그인폼" if self.has_password else "폼"
        return f"{kind}[{self.method.upper()} {self.action or '(self)'}]"


@dataclass
class HttpResult:
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    parse_error: str = ""
    cookies: list[Cookie] = field(default_factory=list)
    forms: list[HttpForm] = field(default_factory=list)
    generator: str = ""                       # <meta name=generator> (CMS 식별)
    app_version: str = ""                     # 본문에서 '앱이름 버전'(예: FreePBX 16.0.40) — 핑거프린트용
    clues: list[str] = field(default_factory=list)   # 본문 단서(경로·링크·주석) — 다음 요청의 실마리

    @property
    def server(self) -> str:
        return self.headers.get("server", "")

    @property
    def location(self) -> str:
        return self.headers.get("location", "")

    @property
    def present_security_headers(self) -> list[str]:
        return [v for k, v in SECURITY_HEADERS.items() if k in self.headers]

    @property
    def missing_security_headers(self) -> list[str]:
        return [v for k, v in SECURITY_HEADERS.items() if k not in self.headers]

    @property
    def has_login_form(self) -> bool:
        return any(f.has_password for f in self.forms)

    def summary(self) -> str:
        bits = [f"HTTP {self.status} {self.reason}".strip()]
        if self.server:
            bits.append(f"Server={self.server}")
        if self.location:
            bits.append(f"→ {self.location}")
        if self.title:
            bits.append(f'title="{self.title}"')
        if self.generator:
            bits.append(f"generator={self.generator}")
        if self.app_version:
            bits.append(f"appver={self.app_version}")
        for k in ("x-powered-by", "www-authenticate"):
            if k in self.headers:
                bits.append(f"{k}={self.headers[k]}")
        if self.cookies:
            bits.append("cookies=" + "; ".join(str(c) for c in self.cookies))
        if self.forms:
            bits.append("forms=" + ", ".join(str(f) for f in self.forms))
        if self.clues:
            bits.append("단서=" + ", ".join(self.clues))
        if self.missing_security_headers:
            bits.append("보안헤더 누락=" + ",".join(self.missing_security_headers))
        return " | ".join(bits)


_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)$", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"'>]+)""", re.I)
# 본문에서 '알려진 웹앱 이름 + 인접 버전'(2마디 이상 점표기)만 추출 → 라이브러리 버전
# (bootstrap-3.3.7 등) 오탐 회피. 앱 이름 뒤 숫자/'<' 아닌 문자 20자 이내에 버전이 와야 매칭.
_APPVER_RE = re.compile(
    r"(?i)(freepbx|elastix|wordpress|joomla|drupal|tomcat|jenkins|grafana|gitlab|gitea|"
    r"phpmyadmin|nextcloud|osticket)[^0-9<\n]{0,20}?(\d+\.\d+(?:\.\d+){0,2})")
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']?([^"'\s>]+)""")


def _parse_cookie(raw: str) -> Cookie:
    """Set-Cookie 한 줄을 파싱(이름 + HttpOnly/Secure/SameSite)."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0]
    c = Cookie(name=name)
    for attr in parts[1:]:
        low = attr.lower()
        if low == "httponly":
            c.httponly = True
        elif low == "secure":
            c.secure = True
        elif low.startswith("samesite"):
            c.samesite = attr.split("=", 1)[1].strip() if "=" in attr else "?"
    return c


def _parse_forms(body: str) -> list[HttpForm]:
    forms: list[HttpForm] = []
    for m in _FORM_RE.finditer(body):
        attrs = dict(_ATTR_RE.findall(m.group(1)))
        inner = m.group(2)
        inputs = [dict(_ATTR_RE.findall(im)).get("name", "")
                  for im in re.findall(r"<input\b[^>]*>", inner, re.I)]
        inputs = [i for i in inputs if i]
        has_pw = bool(re.search(r"""<input[^>]+type=["']?password""", inner, re.I))
        forms.append(HttpForm(action=attrs.get("action", ""),
                              method=(attrs.get("method", "get") or "get").lower(),
                              has_password=has_pw, inputs=inputs))
    return forms


_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#?\s>]{2,60})""", re.I)
# 본문 평문 속 사이트 내부 경로(예: "see /security.txt", "Disallow: /staff-notes/")
_PATH_RE = re.compile(r"(?<![\w/:.])(/[A-Za-z0-9._~-]{2,40}(?:/[A-Za-z0-9._~-]{1,40}){0,3}/?)")


def _body_clues(body: str, limit: int = 5) -> list[str]:
    """본문에서 다음 요청의 실마리가 될 짧은 단서만 추린다(주석·링크·경로).
    요약이 본문을 통째로 버려 단서를 놓치던 문제(벤치 web-version-cve) 보완. 원문은 감사 로그에 남는다."""
    out: list[str] = []

    def add(x: str) -> None:
        x = re.sub(r"\s+", " ", x).strip()[:60]
        if x and x not in out and len(out) < limit:
            out.append(x)
    for m in _COMMENT_RE.finditer(body):
        add("주석:" + m.group(1))
    text = _COMMENT_RE.sub(" ", body)
    for m in _LINK_RE.finditer(text):
        v = m.group(1)
        if not re.match(r"(?i)(?:https?:|//|data:|javascript:|mailto:)", v):
            add(v)
    plain = re.sub(r"<[^>]+>", " ", text)
    for m in _PATH_RE.finditer(plain):
        add(m.group(1))
    return out


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
    cookies_raw: list[str] = []
    for idx, seg in enumerate(segments):
        stripped = seg.strip()
        if not stripped:
            continue   # 빈 구간(연속 빈 줄)은 헤더도 본문 시작도 아님 — 본문 오판 방지
        lines = stripped.splitlines()
        sm = _STATUS_RE.match(lines[0].strip())
        if sm:
            res.status = int(sm.group(1))
            res.reason = sm.group(2).strip()
            res.headers = {}  # 새 응답 시작 → 헤더 리셋
            cookies_raw = []  # 쿠키도 최종 응답 기준
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    key = k.strip().lower()
                    val = v.strip()
                    # Set-Cookie 는 여러 번 올 수 있어 dict 로 덮어쓰지 않고 따로 수집
                    if key == "set-cookie":
                        cookies_raw.append(val)
                    res.headers[key] = val
            seen_status = True
        elif seen_status:
            body = "\r\n\r\n".join(segments[idx:])
            break

    tm = _TITLE_RE.search(body)
    if tm:
        res.title = re.sub(r"\s+", " ", tm.group(1)).strip()
    gm = _GENERATOR_RE.search(body)
    if gm:
        res.generator = gm.group(1).strip()
    am = _APPVER_RE.search(body)
    if am:
        res.app_version = f"{am.group(1)} {am.group(2)}"   # 예: 'FreePBX 16.0.40'
    res.cookies = [_parse_cookie(c) for c in cookies_raw]
    res.forms = _parse_forms(body)
    res.clues = _body_clues(body)
    return res
