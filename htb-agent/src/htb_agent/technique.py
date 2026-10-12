"""
기법 분류(ATT&CK) — 실행한 '명령'을 MITRE ATT&CK 기법으로 라벨링
==================================================================

CTF-Abacus(2608.26237)의 'step별 기법 taxonomy' 축을 **실행 트레이스 기반**으로 결정적
이식한다. `detections.py` 가 '취약점(CWE)→기법'을 매핑한다면, 여기선 '실제 돌린 명령→기법'을
라벨링해 라이트업·벤치 분석이 "어떤 기법을 얼마나 썼나"를 보이게 한다(생성 전용·조회만).
"""
from __future__ import annotations

from .util import binary_of

# 바이너리/키워드 → (ATT&CK 기법 ID, 이름). 보수적 — 모호하면 라벨 안 붙인다(None).
_BINARY: dict[str, tuple[str, str]] = {
    "nmap": ("T1046", "Network Service Discovery"),
    "masscan": ("T1046", "Network Service Discovery"),
    "rustscan": ("T1046", "Network Service Discovery"),
    "gobuster": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "ffuf": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "feroxbuster": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "dirb": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "dirsearch": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "wfuzz": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "nikto": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "whatweb": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "wpscan": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "hydra": ("T1110", "Brute Force"),
    "medusa": ("T1110", "Brute Force"),
    "patator": ("T1110", "Brute Force"),
    "crackmapexec": ("T1110", "Brute Force"),
    "netexec": ("T1110", "Brute Force"),
    "hashcat": ("T1110.002", "Brute Force: Password Cracking"),
    "john": ("T1110.002", "Brute Force: Password Cracking"),
    "searchsploit": ("T1588.005", "Obtain Capabilities: Exploits"),
    "smbclient": ("T1135", "Network Share Discovery"),
    "smbmap": ("T1135", "Network Share Discovery"),
    "enum4linux": ("T1087", "Account Discovery"),
    "enum4linux-ng": ("T1087", "Account Discovery"),
    "rpcclient": ("T1087", "Account Discovery"),
    "ldapsearch": ("T1087.002", "Account Discovery: Domain Account"),
    "kerbrute": ("T1087.002", "Account Discovery: Domain Account"),
    "ssh": ("T1021.004", "Remote Services: SSH"),
    "evil-winrm": ("T1021.006", "Remote Services: WinRM"),
    "psexec.py": ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "secretsdump.py": ("T1003", "OS Credential Dumping"),
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "linpeas.sh": ("T1082", "System Information Discovery"),
    "linpeas": ("T1082", "System Information Discovery"),
    "winpeas": ("T1082", "System Information Discovery"),
    "pspy": ("T1057", "Process Discovery"),
    "nc": ("T1059", "Command and Scripting Interpreter"),
    "ncat": ("T1059", "Command and Scripting Interpreter"),
    "socat": ("T1059", "Command and Scripting Interpreter"),
    "sqlmap": ("T1190", "Exploit Public-Facing Application"),
    "msfconsole": ("T1203", "Exploitation for Client Execution"),
}


def technique_of(cmd: str) -> tuple[str, str] | None:
    """명령 → (ATT&CK ID, 이름) 또는 None(분류 안 함). 바이너리 기준(경로 제거)."""
    if not cmd:
        return None
    return _BINARY.get(binary_of(cmd, strip_path=True))


def coverage(findings) -> list[tuple[str, str]]:
    """실행된(ran) finding 들의 명령에서 쓰인 기법 집합(중복 제거, 첫 등장 순서)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for f in findings or []:
        if not getattr(f, "ran", False):
            continue
        t = technique_of(getattr(f, "command", ""))
        if t and t[0] not in seen:
            seen.add(t[0])
            out.append(t)
    return out


def render_markdown(findings) -> str:
    """실행 트레이스 기법 커버리지를 Markdown 줄로(없으면 안내)."""
    cov = coverage(findings)
    if not cov:
        return "_(실행 트레이스에서 분류된 ATT&CK 기법 없음)_"
    return "\n".join(f"- `{tid}` {name}" for tid, name in cov)
