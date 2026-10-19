"""
Command Validator — 실행 전 명령 검증
====================================================

LLM 이 제안한 명령이 **문법적으로, 그리고 형식적으로(base64·16진수·10진수·
포트·해시) 오류가 없고 실행 가능한지** 를 실행 전에 검증한다.

보장 범위 (과장 금지):
  - 보장함  : 쉘 문법 무오류 / 따옴표·이스케이프 균형 / base64·hex·포트·해시의
              '형식적' 무오류 / 명백한 파괴적 명령 차단 / 바이너리 존재 확인
  - 미보장  : 도구별 옵션의 '의미적' 정확성, 해시가 '정답'인지(평문 없이는 불가),
              명령이 실제로 목표를 달성하는지

검증은 다중 경로로 수행한다: `bash -n` 파싱 + `shlex` 토큰화를
함께 돌려 한쪽이 놓친 문제를 다른 쪽이 잡게 한다.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field


# ── 결과 구조 ────────────────────────────────────────────────────────
@dataclass
class ValidationIssue:
    level: str   # "error" | "warning"
    code: str
    message: str

    def __str__(self) -> str:
        mark = "⛔" if self.level == "error" else "⚠️"
        return f"{mark} [{self.code}] {self.message}"


@dataclass
class ValidationReport:
    command: str
    issues: list[ValidationIssue] = field(default_factory=list)
    binary: str | None = None
    detected: dict = field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        """에러가 하나도 없으면 실행 가능으로 본다(경고는 허용)."""
        return not self.errors

    def summary(self) -> str:
        head = "✅ 통과" if self.ok else "⛔ 거부"
        lines = [f"{head} — $ {self.command}"]
        lines += [f"  {i}" for i in self.issues] or ["  (이슈 없음)"]
        if self.detected:
            for k, v in self.detected.items():
                lines.append(f"  · 탐지[{k}]: {v}")
        return "\n".join(lines)


# ── 형식 검증 헬퍼 (에이전트/도구가 타입을 알 때 직접 호출) ──────────
def validate_base64(s: str, urlsafe: bool = False) -> tuple[bool, str]:
    """base64 문자열이 형식적으로 유효하고 디코딩되는지 검증."""
    s = s.strip()
    if not s:
        return False, "빈 문자열"
    charset = r"A-Za-z0-9\-_" if urlsafe else r"A-Za-z0-9+/"
    if not re.fullmatch(rf"[{charset}]*={{0,2}}", s):
        return False, "base64 문자셋 위반"
    if len(s) % 4 != 0:
        return False, f"길이가 4의 배수가 아님(len={len(s)}, 패딩 오류)"
    try:
        decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        decoder(s, validate=True) if not urlsafe else decoder(s)
        return True, "유효"
    except (binascii.Error, ValueError) as e:
        return False, f"디코딩 실패: {e}"


def validate_hex(s: str) -> tuple[bool, str]:
    s = s.strip().lower()
    s = s[2:] if s.startswith("0x") else s
    if not s:
        return False, "빈 문자열"
    if not re.fullmatch(r"[0-9a-f]+", s):
        return False, "16진수 문자셋 위반"
    return True, "유효"


def validate_decimal(s: str, minimum: int | None = None,
                     maximum: int | None = None) -> tuple[bool, str]:
    s = s.strip()
    if not re.fullmatch(r"[+-]?\d+", s):
        return False, "정수 형식 아님"
    v = int(s)
    if minimum is not None and v < minimum:
        return False, f"{v} < 최소 {minimum}"
    if maximum is not None and v > maximum:
        return False, f"{v} > 최대 {maximum}"
    return True, "유효"


def validate_port_spec(s: str) -> tuple[bool, str]:
    """
    단일 포트/목록/범위(nmap 스타일)를 검증.
    예: "80", "1-1024", "22,80,443", "80-", "-443"
    """
    s = s.strip()
    if not s:
        return False, "빈 포트 지정"
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            for b in (lo, hi):
                if b == "":
                    continue  # 열린 범위 (80- / -443) 허용
                ok, msg = validate_decimal(b, 0, 65535)
                if not ok:
                    return False, f"범위 '{part}' 오류: {msg}"
            if lo and hi and int(lo) > int(hi):
                return False, f"범위 역전: {part}"
        else:
            ok, msg = validate_decimal(part, 0, 65535)
            if not ok:
                return False, f"포트 '{part}' 오류: {msg}"
    return True, "유효"


# ── 해시 형식 테이블 ────────────────────────────────────────────────
# (형식 일치일 뿐, '정답' 여부는 보장하지 않는다. 길이 32 등은 다의적.)
HASH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("MD5/NTLM/LM(32hex·다의적)", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("SHA1(40hex)", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("SHA224(56hex)", re.compile(r"^[a-fA-F0-9]{56}$")),
    ("SHA256(64hex)", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("SHA384(96hex)", re.compile(r"^[a-fA-F0-9]{96}$")),
    ("SHA512(128hex)", re.compile(r"^[a-fA-F0-9]{128}$")),
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("md5crypt", re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("sha256crypt", re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$")),
    ("sha512crypt", re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$")),
    ("MySQL4.1+(*40hex)", re.compile(r"^\*[A-F0-9]{40}$")),
]


def identify_hash(s: str) -> list[str]:
    """형식에 맞는 해시 종류 후보들을 반환(없으면 빈 리스트)."""
    s = s.strip()
    return [name for name, pat in HASH_PATTERNS if pat.match(s)]


def validate_hash(s: str, expected: str | None = None) -> tuple[bool, str]:
    """
    해시가 '형식적으로' 유효한지 검증. expected 를 주면 그 종류에 맞는지 확인.
    """
    kinds = identify_hash(s)
    if not kinds:
        return False, "알려진 해시 형식과 불일치"
    if expected:
        if any(expected.lower() in k.lower() for k in kinds):
            return True, f"{expected} 형식 일치"
        return False, f"{expected} 아님 (후보: {kinds})"
    return True, f"형식 일치 후보: {kinds}"


# ── 파괴적(로컬 공격기 손상) 명령 차단 ──────────────────────────────
_DESTRUCTIVE = [
    (re.compile(r"\brm\s+-rf?\s+(/|/\*|~|\$HOME)(\s|$)"), "루트/홈 재귀 삭제"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "파일시스템 포맷"),
    (re.compile(r"\bdd\b[^|]*\bof=/dev/(sd|nvme|vd)\w*"), "블록디바이스 덮어쓰기"),
    (re.compile(r">\s*/dev/(sd|nvme|vd)\w*"), "블록디바이스로 리다이렉트"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "포크 폭탄"),
    (re.compile(r"\bchmod\s+-R\s+0*777\s+/(\s|$)"), "루트 권한 전면 개방"),
]


# base64 디코드 문맥 (여기 걸린 블롭은 반드시 유효해야 함).
# 인자 토큰을 '넓게' 캡처한다(따옴표 안 전체 / 비공백 / 파이프 전까지) —
# 깨진 문자를 캡처 단계에서 놓치지 않기 위함. 각 패턴의 그룹들 중 매칭된
# 첫 그룹이 블롭이다.
_B64_CTX = [
    re.compile(r"""base64\s+(?:-d|--decode|-D)\s*<<<\s*(?:'([^']*)'|"([^"]*)"|(\S+))"""),
    re.compile(r"""echo\s+(?:-n\s+)?(?:'([^']*)'|"([^"]*)"|([^|]+?))\s*\|\s*base64\s+(?:-d|--decode|-D)"""),
    re.compile(r"""printf\s+(?:'%s'|"%s"|%s)\s+(?:'([^']*)'|"([^"]*)"|(\S+))\s*\|\s*base64\s+(?:-d|--decode|-D)"""),
]


def _first_group(m: re.Match) -> str:
    """정규식 매치에서 매칭된 첫 캡처 그룹을 반환(따옴표/공백 정리)."""
    for g in m.groups():
        if g is not None:
            return g.strip().strip("'\"")
    return ""


def _check_shell_syntax(command: str) -> str | None:
    """bash -n 으로 구문만 파싱(미실행). '' 정상, None 생략(bash 없음), 그 외 에러."""
    bash = shutil.which("bash")
    if not bash:
        return None
    try:
        p = subprocess.run([bash, "-n", "-c", command],
                           capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return "구문 검사 타임아웃"
    if p.returncode != 0:
        return (p.stderr.strip() or "쉘 구문 오류")
    return ""


def _find_binary(tokens: list[str]) -> str | None:
    """선행 환경변수 할당(NAME=VALUE)을 건너뛰고 실제 바이너리 토큰을 찾는다."""
    for t in tokens:
        if re.fullmatch(r"[A-Za-z_]\w*=.*", t):
            continue
        return t
    return None


def validate(command: str, require_known_binary: bool = False) -> ValidationReport:
    """명령을 다중 경로로 검증해 리포트를 반환."""
    report = ValidationReport(command=command)
    cmd = command.strip()
    if not cmd:
        report.issues.append(ValidationIssue("error", "EMPTY", "빈 명령"))
        return report

    # 1) 파괴적 명령
    for pat, desc in _DESTRUCTIVE:
        if pat.search(cmd):
            report.issues.append(ValidationIssue("error", "DESTRUCTIVE",
                                                 f"파괴적 명령 차단: {desc}"))

    # 2) 쉘 문법 (경로 A: bash -n)
    syn = _check_shell_syntax(cmd)
    if syn is None:
        report.issues.append(ValidationIssue("warning", "NO_BASH",
                                             "bash 미설치 — 구문검사 생략(실행환경서 확인)"))
    elif syn:
        report.issues.append(ValidationIssue("error", "SYNTAX", f"쉘 구문 오류: {syn}"))

    # 3) 따옴표/이스케이프 균형 (경로 B: shlex)
    tokens: list[str] | None = None
    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        report.issues.append(ValidationIssue("error", "QUOTE",
                                             f"따옴표/이스케이프 불균형: {e}"))

    # 4) 바이너리 존재
    if tokens:
        binary = _find_binary(tokens)
        report.binary = binary
        if binary and "/" not in binary:
            if shutil.which(binary) is None:
                lvl = "error" if require_known_binary else "warning"
                report.issues.append(ValidationIssue(
                    lvl, "NO_BINARY",
                    f"'{binary}' 미설치 — 실제 실행환경(Kali 등)에서 확인 필요"))

    # 5) base64 문맥 검증
    b64_found = []
    for pat in _B64_CTX:
        for m in pat.finditer(cmd):
            blob = _first_group(m)
            if not blob:
                continue
            ok, msg = validate_base64(blob)
            b64_found.append(blob)
            if not ok:
                report.issues.append(ValidationIssue("error", "BASE64",
                                                     f"base64 블롭 오류: {msg}"))
    if b64_found:
        report.detected["base64"] = b64_found

    # 6) 포트 지정 검증 — '-p' 는 도구마다 의미가 다르다(예: hydra -p=password).
    #    포트 플래그로 쓰는 스캐너에 한해 검증해 오탐을 막는다(감사 발견 A).
    PORT_FLAG_TOOLS = {"nmap", "masscan", "rustscan", "naabu", "unicornscan"}
    base = report.binary.rsplit("/", 1)[-1] if report.binary else ""
    for m in (re.finditer(r"(?:^|\s)-p\s*=?\s*([0-9,\-]+)", cmd)
              if base in PORT_FLAG_TOOLS else []):
        ok, msg = validate_port_spec(m.group(1))
        if not ok:
            report.issues.append(ValidationIssue("error", "PORT", f"포트 지정 오류: {msg}"))
    for m in re.finditer(r"\b[LR]PORT=(\S+)", cmd):
        ok, msg = validate_decimal(m.group(1), 1, 65535)
        if not ok:
            report.issues.append(ValidationIssue("error", "PORT", f"LPORT/RPORT 오류: {msg}"))

    # 7) 해시 형식 탐지 (정보 제공 — 명백 오류만 경고)
    hashes = []
    for tok in (tokens or cmd.split()):
        kinds = identify_hash(tok)
        if kinds:
            hashes.append({tok: kinds})
    if hashes:
        report.detected["hashes"] = hashes

    return report
