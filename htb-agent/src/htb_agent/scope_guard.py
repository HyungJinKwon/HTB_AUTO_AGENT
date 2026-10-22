"""
Scope Guard — 교육용 경계 강제 모듈 (Target-Binding 모델)
=========================================================

이 에이전트는 **권한이 확인된 HTB 머신** 에 한정해서만 동작한다. Scope Guard 는
그 경계를 코드로 못 박는 핵심 안전장치다.

설계(승인제·실행전검증 원칙, 사용자 확정 "2번: 기본거부 + 승인단계 추가확인"):

  1. **Target-Binding** : 세션은 단 하나의 '타겟 IP' 에 바인딩된다. 바인딩 시
     타겟이 허용 HTB 대역 안인지 '한 번' 검증한다. 이후 모든 명령은 이 타겟을
     기준으로 판정된다. (명령 속 점4자리를 전부 타겟으로 긁던 초안의 결함 제거)

  2. **IP 분류** : 명령에 등장하는 각 IP/호스트를 아래로 분류한다.
       · TARGET    — 바인딩된 타겟          → 자동 허용
       · ATTACKER  — 공격자 VPN IP(tun0)    → 자동 허용 (리버스셸/페이로드)
       · LOOPBACK  — 127.0.0.0/8            → 자동 허용
       · UNKNOWN   — 그 외                   → '추가 확인' 대상 (기본 자동통과 거부)

  3. **호스트네임 해석** : machine.htb 같은 vhost 는 /etc/hosts 로 해석해 분류한다.
     해석된 IP 가 타겟이면 통과, 아니거나 미해석이면 추가 확인 대상.

  4. **승인 연동** : UNKNOWN 이 하나라도 있으면 auto_allowed=False → 승인 레이어가
     "이 IP/호스트는 범위 밖입니다. 그래도 실행?" 하고 명시적 재확인을 받는다.
     즉 하드 차단이 아니라 '기본 거부 + 사람이 확인하면 허용'.

  5. **Fail-closed** : 바인딩 전에는 어떤 명령도 검사/실행 대상이 아니다.

  6. **비정규 주소 표기 = 확인 필요** : 가드가 점4자리로 해석하지 못하는 숫자형 호스트
     표기(libc inet_aton 이 수용하는 형태)와 IPv6 리터럴은, 해석 결과와 무관하게 '추가
     확인' 대상으로 올린다. 정상 도구 사용에선 필요 없는 표기이므로 오탐 비용(1회 확인)이
     미탐 비용(범위 이탈)보다 훨씬 작다. 숫자 인자 오탐을 막기 위해 bare 토큰은 네트워크
     도구의 호스트 위치에서만 검사한다.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

logger = logging.getLogger("htb_agent.scope_guard")

# HTB 통상 대역 〔추정 — 통념〕. 런타임 tun0 탐지/ config 로 덮어쓸 것.
DEFAULT_HTB_RANGES: tuple[str, ...] = ("10.10.10.0/23", "10.129.0.0/16")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 스킴 일반화(http 외 ldap/smb/mongodb/ftp 등) — 비-HTTP URL 의 호스트도 분류 대상
_URL_HOST_RE = re.compile(r"[a-z][a-z0-9+.\-]*://(?:[^@/\s\[]+@)?([A-Za-z0-9.\-]+)", re.I)
_URL_V6_RE = re.compile(r"[a-z][a-z0-9+.\-]*://(?:[^@/\s\[]+@)?\[([^\]\s]+)\]", re.I)
# 숫자형 호스트 표기(1~4 파트, 각 10진/0x16진/0선행 8진) — inet_aton 수용 형태 후보
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.I)
# bare 토큰을 호스트로 받는 네트워크 도구(이 도구들의 호스트 위치에서만 숫자형 표기 검사)
_NET_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "telnet", "ftp",
    "tftp", "ping", "traceroute", "nmap", "masscan", "rustscan", "naabu", "nikto", "whatweb",
    "hydra", "medusa", "ncrack", "smbclient", "smbmap", "rpcclient", "enum4linux",
    "enum4linux-ng", "nxc", "netexec", "crackmapexec", "evil-winrm", "xfreerdp", "rdesktop",
    "mysql", "psql", "redis-cli", "mongo", "mongosh", "ldapsearch", "kerbrute", "dig",
    "nslookup", "host", "snmpwalk", "snmpget", "onesixtyone", "showmount", "rsync", "sqlmap",
    "wpscan", "ffuf", "gobuster", "feroxbuster", "wfuzz", "dirb", "http", "openssl",
}
_WRAPPERS = {"sudo", "proxychains", "proxychains4", "torsocks", "env", "nohup", "stdbuf"}
_HOSTLIKE_RE = re.compile(r"^[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+$")
# _NONHOST_EXT 중 실제 TLD 와 겹치는 확장자(IANA 대조). 일반 토큰에선 파일로 보되(오탐
# 방지), 네트워크 도구의 호스트 위치에 오면 호스트로 분류한다(fail-open 방지).
_TLD_COLLIDING_EXT = {"md", "py", "sh", "so", "zip"}
# 리다이렉트 연산자 — 바로 뒤 토큰은 파일
_REDIRECTS = {"<", ">", ">>", "<<", "2>", "2>>", "1>", "&>", ">|"}
# 원격 호스트를 '호스트:경로' 로만 받는 도구 — ':' 없는 인자는 로컬 파일
_COLON_HOST_TOOLS = {"scp", "rsync"}
# 호스트로 오인하기 쉬운 파일 확장자(점 포함 토큰) 제외 → 오탐 방지.
# ⚠ 규칙: 실제 TLD 와 겹치는 확장자는 추가 금지 — 그 TLD 의 진짜 호스트가 파일로
#   오인돼 범위 검사를 통과(fail-open)한다. 아래 추가분은 IANA TLD 목록
#   (data.iana.org/TLD/tlds-alpha-by-domain.txt, 2026-10-06 판)과 대조해 겹치지 않음을
#   확인했다. 첫 줄 원본 목록의 md·py·sh·so·zip 은 TLD 와 겹치는 기존 항목이다.
_NONHOST_EXT = {
    "nse", "txt", "sh", "py", "html", "htm", "php", "xml", "json", "yaml", "yml",
    "conf", "cfg", "log", "md", "js", "css", "asp", "aspx", "jsp", "bak", "zip",
    "tar", "gz", "csv", "pdf", "png", "jpg", "exe", "dll", "so",
    # 바이너리·이미지·캡처·DB·키/인증서(전부 비-TLD)
    "bin", "elf", "out", "img", "iso", "raw", "dmp", "pcap", "pcapng", "cap",
    "db", "sqlite", "sqlite3", "kdbx", "dat", "sav", "pem", "crt", "cer", "der",
    "pfx", "p12", "key", "keytab", "ccache", "kirbi", "ovpn",
    # 패키지·아카이브·가상디스크
    "jar", "war", "apk", "whl", "deb", "rpm", "class", "pyc", "rar", "tgz", "bz2",
    "xz", "7z", "zst", "lzma", "vmdk", "vhd", "vhdx", "ova",
    # 문서·스크립트·소스·설정·스캔 산출물
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "pptx", "odt", "epub", "chm",
    "ps1", "psm1", "bat", "vbs", "hta", "reg", "lnk", "msi", "evtx", "sys", "efi",
    "c", "h", "cpp", "hpp", "go", "rb", "lua", "ts", "ini", "toml", "sql",
    "hash", "hashes", "lst", "dic", "swp", "orig", "tmp", "old", "nmap", "gnmap",
    "mp4", "wav",
}


class ScopeViolation(Exception):
    """허용 범위를 벗어났거나 전제(바인딩)가 깨졌을 때 발생."""


class IPClass(str, Enum):
    TARGET = "target"
    ATTACKER = "attacker"
    LOOPBACK = "loopback"
    UNKNOWN = "unknown"


@dataclass
class CommandScopeResult:
    command: str
    classified: list[tuple[str, IPClass, str]] = field(default_factory=list)
    needs_confirmation: list[str] = field(default_factory=list)

    @property
    def auto_allowed(self) -> bool:
        """추가확인 대상이 없으면 (타겟/공격자/loopback 뿐) 자동 허용."""
        return not self.needs_confirmation

    def summary(self) -> str:
        head = "✅ 범위내(자동허용)" if self.auto_allowed else "⚠️ 추가확인 필요"
        lines = [f"{head} — $ {self.command}"]
        for tok, cls, note in self.classified:
            lines.append(f"  · {tok} → {cls.value}" + (f" {note}" if note else ""))
        if self.needs_confirmation:
            lines.append(f"  ⚠️ 범위 밖/미해석: {self.needs_confirmation}")
        if not self.classified:
            lines.append("  · (네트워크 대상 없음 — 로컬 명령)")
        return "\n".join(lines)


def normalize_target(raw: str) -> str:
    """타겟 문자열에서 스킴(http://)·경로·포트(:1337)를 제거해 호스트/IP만 남긴다."""
    t = raw.strip()
    m = _URL_HOST_RE.match(t)
    if m:
        return m.group(1).strip()
    t = t.split("/", 1)[0]
    # IPv4:port 또는 host:port 에서 포트 제거(IPv6 미지원이라 단순 rsplit 안전)
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def decode_ipv4_literal(token: str) -> str | None:
    """숫자형 호스트 표기를 inet_aton(3) 규칙으로 점4자리 IPv4 로 정규화.
    1~4 파트(a / a.b / a.b.c / a.b.c.d), 각 파트 10진·0x16진·0선행 8진.
    해석 불가하면 None. (curl·ping·wget 등 libc 해석기가 같은 규칙을 쓴다)"""
    t = (token or "").strip().lower()
    if not t or not _NUMERIC_HOST_RE.fullmatch(t):
        return None
    parts: list[int] = []
    for p in t.split("."):
        if p.startswith("0x"):
            if len(p) == 2:
                return None
            v = int(p, 16)
        elif len(p) > 1 and p.startswith("0"):
            if any(c not in "01234567" for c in p):
                return None
            v = int(p, 8)
        else:
            v = int(p)
        parts.append(v)
    n = len(parts)
    if any(v > 255 for v in parts[:-1]) or parts[-1] >= 1 << (8 * (5 - n)):
        return None
    val = 0
    for v in parts[:-1]:
        val = (val << 8) | v
    val = (val << (8 * (5 - n))) | parts[-1]
    return str(ipaddress.IPv4Address(val))


def _ipv6_literal(token: str) -> ipaddress.IPv6Address | None:
    """IPv6 리터럴(대괄호·zone 허용)이면 주소, 아니면 None."""
    t = (token or "").strip().strip("[]").split("%", 1)[0]
    if t.count(":") < 2:
        return None
    try:
        return ipaddress.IPv6Address(t)
    except ValueError:
        return None


def _host_position_tokens(command: str) -> list[tuple[str, bool]]:
    """네트워크 도구 명령에서 호스트 위치 후보 토큰을 (토큰, positional) 로 뽑는다.
    positional=False 는 옵션 바로 뒤 값(--opt val / --opt=val). user@·:port 는 제거.
    URL(://)은 URL 경로가 처리하므로 제외. 파이프·;·&& 로 나뉜 각 구간을 따로 본다."""
    out: list[tuple[str, bool]] = []
    for seg in re.split(r"\|\|?|&&|;|&|\n", command):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if re.fullmatch(r"[A-Za-z_]\w*=.*", t) or t in _WRAPPERS:
                i += 1
                continue
            if t == "timeout":
                i += 1
                while i < len(toks) and (toks[i].startswith("-") or toks[i][:1].isdigit()):
                    i += 1
                continue
            break
        if i >= len(toks):
            continue
        binary = toks[i].rsplit("/", 1)[-1].lower()
        if binary not in _NET_TOOLS and not binary.startswith("impacket-"):
            continue
        after_opt = False
        skip_next = False
        for t in toks[i + 1:]:
            if skip_next:              # 리다이렉트 대상(파일)
                skip_next = False
                continue
            if t in _REDIRECTS:
                skip_next = True
                continue
            if t.startswith("-"):
                if "=" in t:
                    out.append((t.split("=", 1)[1], False))
                after_opt = True
                continue
            if binary in _COLON_HOST_TOOLS and ":" not in t:
                after_opt = False      # scp/rsync: ':' 없는 인자는 로컬 경로
                continue
            if "://" not in t:
                c = t.rsplit("@", 1)[-1]
                if c.count(":") == 1:
                    c = c.split(":", 1)[0]
                out.append((c, not after_opt))
                if binary == "ssh" and not after_opt:
                    break              # ssh: 첫 위치 인자만 호스트, 나머지는 원격 명령
            after_opt = False
    return out


def _needs_numeric_check(tok: str, positional: bool) -> bool:
    """bare 숫자형 토큰을 '비정규 주소 표기'로 볼지(오탐 억제 규칙).
    단일 숫자는 2^24 이상만(포트·카운트 제외), 2~3 파트는 위치 인자이거나 비10진
    파트가 있을 때만(옵션 값 2.5 등 제외), 4 파트는 정규 점4자리가 아닐 때만."""
    parts = tok.lower().split(".")
    nondec = any(p.startswith("0x") or (len(p) > 1 and p.startswith("0")) for p in parts)
    if len(parts) == 1:
        dec = decode_ipv4_literal(tok)
        return dec is not None and int(ipaddress.IPv4Address(dec)) >= 1 << 24
    if len(parts) in (2, 3):
        return positional or nondec
    return not _IPV4_RE.fullmatch(tok)


@dataclass
class ScopeGuard:
    # 타입 표기만 IPv4|IPv6 로(ip_address/ip_network 의 실제 반환형) — 동작은 그대로(IPv6 타겟은 bind 에서 거부)
    allowed_target_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    bound_target: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    attacker_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=set)
    enforce_ranges: bool = True            # False=단일 타겟 바인딩(CTF/Dreamhack)
    allow_hostname_target: bool = False    # 호스트명 타겟 허용(CTF)
    bound_host: str | None = None          # 호스트명 타겟(해석 전/불가 시)

    # ── 생성 ────────────────────────────────────────────────────────
    @classmethod
    def from_cidr_strings(cls, cidrs: Iterable[str] | None = None,
                          enforce_ranges: bool = True,
                          allow_hostname_target: bool = False) -> "ScopeGuard":
        raw = list(cidrs) if cidrs else (list(DEFAULT_HTB_RANGES) if enforce_ranges else [])
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for c in raw:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError as exc:
                raise ValueError(f"잘못된 CIDR 설정: {c!r} ({exc})") from exc
        if enforce_ranges and not nets:
            raise ValueError("Scope Guard: 허용 대역이 비어 있습니다. fail-closed.")
        logger.info("Scope Guard — 대역강제=%s, 허용 대역: %s",
                    enforce_ranges, [str(n) for n in nets])
        return cls(allowed_target_cidrs=nets, enforce_ranges=enforce_ranges,
                   allow_hostname_target=allow_hostname_target)

    # ── 타겟 바인딩 ─────────────────────────────────────────────────
    def bind_target(self, ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """
        타겟을 세션에 바인딩한다.
          - 대역강제(HTB): 허용 대역 안인지 '한 번' 검증.
          - 단일타겟(CTF): 명시한 IP 를 그대로 허용(/32 추가). 호스트명도 허용 가능.
        호스트명 타겟이면 IPv4 주소는 None 을 반환(bound_host 로 추적).
        """
        host = normalize_target(ip)
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # IP 가 아님 → 호스트명 타겟
            if not self.allow_hostname_target:
                raise ScopeViolation(
                    f"타겟 파싱 실패: {ip!r} (호스트명 타겟은 CTF/Dreamhack 모드에서만)."
                )
            self.bound_host = host.lower()
            resolved = self.load_etc_hosts().get(self.bound_host)
            if resolved:
                resolved_addr = ipaddress.ip_address(resolved)
                self.bound_target = resolved_addr
                self._allow(resolved_addr)
            logger.info("호스트명 타겟 바인딩: %s (해석: %s)", self.bound_host, resolved or "미해석")
            return self.bound_target
        if isinstance(addr, ipaddress.IPv6Address):
            raise ScopeViolation("현재 IPv4 타겟만 지원합니다(IPv6 미지원).")
        if self.enforce_ranges and not any(addr in net for net in self.allowed_target_cidrs):
            raise ScopeViolation(
                f"타겟 {addr} 은(는) 허용 HTB 대역({self.describe()}) 밖입니다. 바인딩 거부."
            )
        if not self.enforce_ranges:
            self._allow(addr)      # 단일 타겟 모드: 명시한 타겟만 /32 허용
        self.bound_target = addr
        logger.info("타겟 바인딩: %s", addr)
        return addr

    def _allow(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        net = ipaddress.ip_network(f"{addr}/32")
        if net not in self.allowed_target_cidrs:
            self.allowed_target_cidrs.append(net)

    def add_attacker_ip(self, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise ValueError(f"공격자 IP 파싱 실패: {ip!r}") from exc
        self.attacker_ips.add(addr)
        logger.info("공격자 VPN IP 등록: %s", addr)

    # 공격자 VPN IP 자동탐지는 environment.detect_vpn_ips() 하나로 일원화한다(중복 제거).
    # (예전 ScopeGuard.detect_attacker_ips() 는 동일 로직 사본·미사용이라 제거)

    # ── 분류 ────────────────────────────────────────────────────────
    def classify_ip(self, ip: str) -> IPClass:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return IPClass.UNKNOWN
        if self.bound_target is not None and addr == self.bound_target:
            return IPClass.TARGET
        if addr in self.attacker_ips:
            return IPClass.ATTACKER
        if addr.is_loopback:
            return IPClass.LOOPBACK
        return IPClass.UNKNOWN

    # ── 명령 검사 ───────────────────────────────────────────────────
    def inspect_command(self, command: str,
                        hosts_map: dict[str, str] | None = None) -> CommandScopeResult:
        """명령 속 IP/호스트를 분류한다. 바인딩 전에는 fail-closed."""
        if self.bound_target is None and self.bound_host is None:
            raise ScopeViolation("타겟이 바인딩되지 않았습니다. bind_target() 먼저 호출하세요.")
        hosts_map = hosts_map if hosts_map is not None else self.load_etc_hosts()
        result = CommandScopeResult(command=command)

        for ip in _IPV4_RE.findall(command):
            cls = self.classify_ip(ip)
            dec = decode_ipv4_literal(ip)
            note = f"(비정규 표기→{dec})" if (cls == IPClass.UNKNOWN and dec and dec != ip) else ""
            result.classified.append((ip, cls, note))
            if cls == IPClass.UNKNOWN:
                result.needs_confirmation.append(ip)

        for raw in _URL_V6_RE.findall(command):
            self._flag_ipv6(result, raw)

        seen_tok: set[str] = set()
        for tok, positional in _host_position_tokens(command):
            if tok in seen_tok:
                continue
            if _ipv6_literal(tok):
                seen_tok.add(tok)
                self._flag_ipv6(result, tok)
            elif _needs_numeric_check(tok, positional):
                dec = decode_ipv4_literal(tok)
                if dec:
                    seen_tok.add(tok)
                    self._flag_encoded(result, tok, dec)

        hosts = self._extract_hosts(command)
        # TLD 와 겹치는 확장자(sh·py 등)는 일반 토큰에선 파일로 보지만, 네트워크 도구의
        # 호스트 위치(위치 인자)에 오면 호스트로 분류한다 — 'curl evil.sh' 미탐 방지.
        for tok, positional in _host_position_tokens(command):
            t = tok.strip().lower()
            if (positional and _HOSTLIKE_RE.fullmatch(t) and re.search(r"[a-z]", t)
                    and t.rsplit(".", 1)[-1] in _TLD_COLLIDING_EXT):
                hosts.add(t)
        for host in sorted(hosts):
            # CTF 호스트명 타겟: 바인딩된 호스트는 TARGET 으로 자동 허용
            if self.bound_host is not None and host.lower() == self.bound_host:
                result.classified.append((host, IPClass.TARGET, "(바인딩 타겟)"))
                continue
            dec = decode_ipv4_literal(host)
            if dec:                              # URL 의 숫자형 호스트(비정규 표기)
                if host not in seen_tok:
                    seen_tok.add(host)
                    self._flag_encoded(result, host, dec)
                continue
            # ffuf/wfuzz vhost 퍼징: 'FUZZ.<도메인>' 은 <도메인> 의 '서브도메인 퍼징'이다. 부모
            # 도메인이 in-scope(hosts_map 등록 vhost 또는 바인딩 타겟)면 그 분류를 그대로 적용한다
            # — 서브도메인 열거는 in-scope 작업. 부모가 범위 밖이면 이 분기를 타지 않고 아래 일반
            # 경로로 떨어져 '미해석 → 확인 필요'로 거부된다(FUZZ.evil.com → evil.com → 범위 밖,
            # 우회 아님). FUZZ 는 ffuf 의 고정 키워드(명령에서 소문자화되어 'fuzz' 로 들어온다).
            labels = host.split(".")
            if len(labels) >= 3 and labels[0] == "fuzz":
                parent = ".".join(labels[1:])
                presolved = hosts_map.get(parent)
                if presolved:
                    cls = self.classify_ip(presolved)
                    result.classified.append((host, cls, f"(vhost 퍼징 → {parent}→{presolved})"))
                    if cls == IPClass.UNKNOWN:
                        result.needs_confirmation.append(f"{host}({presolved})")
                    continue
                if self.bound_host is not None and parent == self.bound_host:
                    result.classified.append((host, IPClass.TARGET, "(vhost 퍼징 → 바인딩 타겟)"))
                    continue
            resolved = hosts_map.get(host.lower())
            if resolved:
                cls = self.classify_ip(resolved)
                result.classified.append((host, cls, f"→{resolved}"))
                if cls == IPClass.UNKNOWN:
                    result.needs_confirmation.append(f"{host}({resolved})")
            else:
                if host.endswith(".htb") or host.endswith(".local"):
                    note = "미해석(/etc/hosts에 추가 필요)"
                    result.needs_confirmation.append(f"{host}(미해석)")
                else:
                    note = "외부도메인(미해석)"
                    result.needs_confirmation.append(f"{host}(외부)")
                result.classified.append((host, IPClass.UNKNOWN, note))

        return result

    # ── 보조 ────────────────────────────────────────────────────────
    def _flag_encoded(self, result: CommandScopeResult, tok: str, dec: str) -> None:
        """비정규 숫자형 표기: 해석 결과와 무관하게 확인 필요(fail-closed)."""
        result.classified.append((tok, self.classify_ip(dec), f"(비정규 표기→{dec} · 확인 필요)"))
        result.needs_confirmation.append(f"{tok}(→{dec})")

    def _flag_ipv6(self, result: CommandScopeResult, raw: str) -> None:
        """IPv6 리터럴: ::1 만 loopback 허용, 그 외는 미지원 → 확인 필요."""
        addr = _ipv6_literal(raw)
        if addr is not None and addr == ipaddress.IPv6Address("::1"):
            result.classified.append((raw, IPClass.LOOPBACK, "(IPv6 loopback)"))
            return
        result.classified.append((raw, IPClass.UNKNOWN, "(IPv6 — 미지원 · 확인 필요)"))
        result.needs_confirmation.append(f"{raw}(IPv6)")

    @staticmethod
    def _extract_hosts(command: str) -> set[str]:
        hosts: set[str] = set()
        for m in _URL_HOST_RE.finditer(command):
            h = m.group(1).lower()
            if _IPV4_RE.fullmatch(h):
                continue  # IP 리터럴은 IP 경로가 처리 → 호스트로 중복 포착 금지
            hosts.add(h)
        for tok in re.split(r"[\s=,'\"|;()<>]+", command):
            t = tok.strip().lower()
            if not t or "/" in t:
                continue
            if _IPV4_RE.fullmatch(t):
                continue
            if not _HOSTLIKE_RE.fullmatch(t):
                continue
            if not re.search(r"[A-Za-z]", t):
                continue
            if t.rsplit(".", 1)[-1] in _NONHOST_EXT:
                continue
            hosts.add(t)
        return hosts

    @staticmethod
    def load_etc_hosts(path: str = "/etc/hosts") -> dict[str, str]:
        """/etc/hosts 를 {호스트명(lower): IP} 로 읽는다(HTB vhost 워크플로)."""
        mapping: dict[str, str] = {}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    ip = parts[0]
                    if not _IPV4_RE.fullmatch(ip):
                        continue
                    for name in parts[1:]:
                        mapping.setdefault(name.lower(), ip)
        except OSError:
            pass
        return mapping

    def describe(self) -> str:
        if self.allowed_target_cidrs:
            return ", ".join(str(n) for n in self.allowed_target_cidrs)
        if self.bound_host:
            return f"단일 타겟: {self.bound_host}"
        return "(단일 타겟 모드 — 바인딩 대기)"
