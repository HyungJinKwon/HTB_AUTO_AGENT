"""
Writeup Generator — 풀이 라이트업 자동 생성 (htb-ctf-writeup-v5 구조)
=====================================================================

오케스트레이션 결과(OrchestrationReport)를 순수 Markdown 라이트업으로 변환한다.

§7 규약 준수:
  - 순수 Markdown (HTML 태그 배제).
  - 플레이스홀더 형식: <타겟 IP> / <공격자 VPN IP> / <머신명> / <호스트명> / <유저명>
  - 포트표, 명령 3분할 해설, 공격 시나리오 요약표.
  - 레드/블루 밸런스(§1): 블루팀 탐지 지표(SIEM Event ID, Snort/Suricata,
    Wireshark 필터, 체크리스트)를 관측 포트에 맞춰 포함.
"""

from __future__ import annotations

from .approval import explain_command


def _flag_line(report, kind: str, fallback: str) -> str:
    """캡처된 플래그가 있으면 값, 없으면 안내 문구."""
    val = report.user_flag if kind == "user" else report.root_flag
    if val:
        return f"`{val}`  ✅ 획득"
    return f"미획득 ({fallback})"


# 포트별 블루팀 탐지 지표 (관측된 포트에만 출력)
_BLUE: dict[int, dict] = {
    21: {"svc": "FTP", "siem": "FTP 로그인 성공/실패 로그",
         "ids": 'alert tcp any any -> $HOME_NET 21 (msg:"FTP anon login"; content:"USER anonymous";)',
         "wireshark": "ftp || ftp-data", "check": "익명 로그인 허용 여부, 평문 자격증명 노출"},
    22: {"svc": "SSH", "siem": "auth.log: Failed/Accepted password, Event 4625 등가",
         "ids": 'alert tcp any any -> $HOME_NET 22 (msg:"SSH brute"; threshold:type both,track by_src,count 5,seconds 60;)',
         "wireshark": "ssh", "check": "비밀번호 인증 비활성화, fail2ban, 키기반 인증"},
    80: {"svc": "HTTP", "siem": "웹 access.log 비정상 경로/상태코드 급증",
         "ids": 'alert http any any -> $HOME_NET any (msg:"Dir brute"; threshold:type threshold,track by_src,count 50,seconds 10;)',
         "wireshark": "http.request", "check": "디렉토리 브루트포싱 탐지, WAF, 디렉토리 리스팅"},
    443: {"svc": "HTTPS", "siem": "TLS 핸드셰이크 이상, 웹 access.log",
          "ids": 'alert tls any any -> $HOME_NET 443 (msg:"TLS scan";)',
          "wireshark": "tls.handshake", "check": "취약 암호군, 인증서, 경로 탐색"},
    139: {"svc": "NetBIOS/SMB", "siem": "Event 5140/5145 (공유 접근)",
          "ids": 'alert tcp any any -> $HOME_NET 445 (msg:"SMB enum";)',
          "wireshark": "smb || smb2 || nbss", "check": "널 세션, 익명 공유 열거"},
    445: {"svc": "SMB", "siem": "Event 5140(공유)/5145(상세)/4624(로그온)",
          "ids": 'alert smb any any -> $HOME_NET 445 (msg:"SMB access";)',
          "wireshark": "smb2", "check": "쓰기가능 공유, 널세션, SMBv1(EternalBlue)"},
    88: {"svc": "Kerberos", "siem": "Event 4768(TGT)/4769(TGS)/4771(사전인증 실패)",
         "ids": 'alert tcp any any -> $HOME_NET 88 (msg:"Kerberos activity";)',
         "wireshark": "kerberos", "check": "AS-REP/Kerberoasting(4769 급증), 사전인증 비활성 계정"},
    389: {"svc": "LDAP", "siem": "Event 2889(비서명 바인드), DC 로그",
          "ids": 'alert tcp any any -> $HOME_NET 389 (msg:"LDAP query";)',
          "wireshark": "ldap", "check": "익명 바인드, LDAP 서명 미적용"},
    3389: {"svc": "RDP", "siem": "Event 4624 LogonType 10, 4625",
           "ids": 'alert tcp any any -> $HOME_NET 3389 (msg:"RDP brute";)',
           "wireshark": "rdp || tpkt", "check": "NLA, 계정 잠금 정책, 무차별 대입"},
    5985: {"svc": "WinRM", "siem": "Event 4624, WinRM 운영 로그",
           "ids": 'alert tcp any any -> $HOME_NET 5985 (msg:"WinRM";)',
           "wireshark": "http && tcp.port==5985", "check": "자격증명 재사용, PSRemoting 제한"},
}


def _port_table(host) -> str:
    rows = ["| 포트 | 프로토콜 | 서비스 | 버전/배너 |", "|---|---|---|---|"]
    for p in host.ports:
        if p.state == "open":
            rows.append(f"| {p.port} | {p.proto} | {p.service or '-'} | {p.banner or '-'} |")
    if len(rows) == 2:
        rows.append("| - | - | (열린 포트 없음) | - |")
    return "\n".join(rows)


def _collect_commands(report) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if report.recon:
        for a in report.recon.attempts:
            if a.ran:
                out.append((a.label, a.command))
    for f in report.enum_findings + report.llm_findings:
        if f.ran:
            out.append(("enum", f.command))
    return out


def _cmd_explanations(report) -> str:
    cmds = _collect_commands(report)
    if not cmds:
        return "_(실행된 명령 없음 — 실제 Kali 환경에서 실행 시 채워짐)_"
    blocks = []
    for label, cmd in cmds:
        blocks.append(f"**[{label}]** `{cmd}`\n\n```\n{explain_command(cmd)}\n```")
    return "\n\n".join(blocks)


def _scenario_table(report) -> str:
    rows = ["| 단계 | 기법/명령 | 결과 |", "|---|---|---|"]
    rows.append(f"| 정찰 | nmap 포트 스캔 | 열린 포트 {len(report.host.open_ports) if report.host else 0}개 |")
    if report.profile:
        rows.append(f"| 식별 | 서비스/배너 분석 | OS={report.profile.os_class.value} |")
    for f in (report.enum_findings + report.llm_findings):
        if f.ran and f.output:
            rows.append(f"| 열거 | `{f.command}` | {f.output[:60]} |")
    for m in report.vuln_matches:
        rows.append(f"| 취약점 | {m.name} | {' '.join(m.cve) or '-'} |")
    rows.append("| 초기 침투 | <기법> | user.txt |")
    rows.append("| 권한 상승 | <기법> | root.txt |")
    return "\n".join(rows)


def _blue_team(host) -> str:
    open_ports = host.open_ports if host else []
    present = [p for p in open_ports if p in _BLUE]
    if not present:
        return "_(관측된 포트에 대한 매핑 없음 — 포트 추가 시 자동 생성)_"
    lines = []
    for p in present:
        b = _BLUE[p]
        lines.append(f"### {p}/{b['svc']}")
        lines.append(f"- **SIEM**: {b['siem']}")
        lines.append(f"- **Snort/Suricata**:\n  ```\n  {b['ids']}\n  ```")
        lines.append(f"- **Wireshark 필터**: `{b['wireshark']}`")
        lines.append(f"- **점검 체크리스트**: {b['check']}")
    return "\n".join(lines)


def generate_writeup(report, machine_name: str = "<머신명>",
                     attacker_ip: str | None = None,
                     difficulty: str = "<난이도>",
                     hostname: str = "<호스트명>",
                     username: str = "<유저명>") -> str:
    atk = attacker_ip or "<공격자 VPN IP>"
    os_line = "-"
    if report.profile:
        os_line = f"{report.profile.os_class.value} ({report.profile.tag})"

    vuln_lines = []
    if report.detected_cve:
        vuln_lines.append(f"- 탐지 CVE: {', '.join(report.detected_cve)}")
    if report.detected_cwe:
        vuln_lines.append(f"- 탐지 CWE: {', '.join(report.detected_cwe)}")
    for m in report.vuln_matches:
        sev = f"[{m.severity}] " if m.severity else ""
        vuln_lines.append(f"- {sev}**{m.name}** ({' '.join(m.cve + m.cwe)}) — {m.note}")
        for s in m.suggest:
            vuln_lines.append(f"  - 제안: `{s}`")
    vuln_block = "\n".join(vuln_lines) or "_(명시적 CVE/CWE 미탐지 — 수동 분석 필요)_"
    one_day_block = _one_day_block(report)

    foothold = []
    for m in report.vuln_matches:
        for s in m.suggest:
            foothold.append(f"- `{s}`  (취약점: {m.name})")
    for s in report.manual_suggestions:
        foothold.append(f"- {s}")
    foothold_block = "\n".join(foothold) or "- _(수동 분석 필요)_"

    md = f"""# {machine_name} — HTB 라이트업

> 권한이 확인된 HTB 머신 대상 학습용 라이트업. 플레이스홀더(`<...>`)는 실제 값으로 교체.

## 0. 개요

- 머신명: {machine_name}
- 타겟 IP: {report.target}
- 공격자 VPN IP: {atk}
- 운영체제: {os_line}
- 난이도: {difficulty}
- 호스트명: {hostname}

## 1. 정찰 (Reconnaissance)

### 1.1 포트 스캔

{_port_table(report.host) if report.host else "_(스캔 결과 없음)_"}

### 1.2 실행 명령 (바이너리 / 옵션 / 파라미터 3분할 해설)

{_cmd_explanations(report)}

## 2. 열거 (Enumeration)

{_enum_section(report)}

## 3. 취약점 분석 (Vulnerability Analysis)

{vuln_block}

### 3.1 1-day 메타데이터 후보

{one_day_block}

## 4. 공격 시나리오 요약

{_scenario_table(report)}

## 5. 초기 침투 (Foothold)

{foothold_block}

- user.txt: {_flag_line(report, "user", username)}

## 6. 권한 상승 (Privilege Escalation)

- _(수동 분석: SUID/sudo, 커널, 서비스 오구성, AD 공격경로 등)_
- root.txt: {_flag_line(report, "root", "관리자 권한 획득 후")}

## 7. 블루팀 탐지 지표 (Blue Team)

{_blue_team(report.host)}

## 8. 마무리 체크리스트

- [ ] 모든 열린 포트/서비스 열거 완료
- [ ] 탐지된 CVE/CWE 수동 검증
- [ ] user.txt / root.txt 획득
- [ ] 블루팀 관점 탐지/완화 방안 정리

---
_자동 생성(htb-agent). 사용자 제공 자료·관측 기반, 외부 라이트업 미참조._
"""
    return md


def _enum_section(report) -> str:
    lines = []
    for f in report.enum_findings + report.llm_findings:
        if f.ran and f.output:
            lines.append(f"- `{f.command}`\n  - {f.output}")
    return "\n".join(lines) or "_(자동 열거 결과 없음 — 실제 실행 시 채워짐)_"


def _one_day_block(report) -> str:
    """Public advisory metadata is evidence to verify, never an execution instruction."""
    lines = []
    for lead in getattr(report, "one_day_leads", [])[:10]:
        source = str(lead.get("source", "source"))
        identifier = str(lead.get("id", "?"))
        title = " ".join(str(lead.get("title", "")).split())[:180]
        url = str(lead.get("url", ""))
        lines.append(f"- **미검증 {source} 후보** `${identifier}`: {title} ({url})")
    for warning in getattr(report, "one_day_warnings", []):
        lines.append(f"- ⚠️ {warning}")
    return "\n".join(lines) or "_(후보 없음 — 로컬 SearchSploit 또는 관측 CVE를 수동 확인)_"


# ──────────────────────────────────────────────────────────────────────
# Tistory 보안 블로그 13섹션 템플릿 (elpam_security_tistory_FINAL 구조)
# §7: 포트·프로토콜/아키텍처 다이어그램·공격 시나리오표·블루팀 탐지 지표·
#     3분할 명령 해설·고급 조합 예시·내장 셸 명령 매핑. 순수 Markdown.
# ──────────────────────────────────────────────────────────────────────

def _arch_diagram(host, target: str, attacker: str) -> str:
    svcs = ", ".join(f"{p.port}/{p.service or '?'}" for p in host.ports
                     if p.state == "open") if host else "(미상)"
    return ("```\n"
            f"[공격자 {attacker}]\n"
            f"      | HTB VPN (tun0)\n"
            f"      v\n"
            f"[타겟 {target}]  열린 서비스: {svcs}\n"
            "```")


def _shell_cmd_map(os_class: str) -> str:
    if os_class.startswith("windows"):
        rows = [
            ("현재 권한", "whoami /all"),
            ("시스템 정보", "systeminfo"),
            ("로컬 사용자", "net user"),
            ("도메인 관리자", 'net group "Domain Admins" /domain'),
            ("네트워크", "ipconfig /all"),
            ("예약 작업", "schtasks /query /fo LIST /v"),
        ]
    else:
        rows = [
            ("현재 권한", "id; whoami"),
            ("커널/배포판", "uname -a; cat /etc/os-release"),
            ("sudo 권한", "sudo -l"),
            ("SUID 바이너리", "find / -perm -4000 -type f 2>/dev/null"),
            ("사용자 목록", "cat /etc/passwd"),
            ("크론", "cat /etc/crontab; ls -la /etc/cron.*"),
        ]
    out = ["| 목적 | 명령 |", "|---|---|"]
    out += [f"| {k} | `{v}` |" for k, v in rows]
    return "\n".join(out)


def _advanced_combos(host, target: str) -> str:
    ports = host.open_ports if host else []
    combos = []
    if any(p in ports for p in (80, 443, 8080)):
        combos.append("ffuf -u http://{t}/FUZZ -w wordlist.txt -mc 200,301,302 -fs 0".replace("{t}", target))
        combos.append("gobuster vhost -u http://{t} -w subdomains.txt --append-domain".replace("{t}", target))
    if any(p in ports for p in (139, 445)):
        combos.append("netexec smb {t} -u users.txt -p pass.txt --continue-on-success".replace("{t}", target))
    if 88 in ports:
        combos.append("impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip {t} -no-pass".replace("{t}", target))
        combos.append("impacket-GetUserSPNs DOMAIN/user:pass -dc-ip {t} -request".replace("{t}", target))
    if 22 in ports:
        combos.append("hydra -L users.txt -P pass.txt ssh://{t} -t 4".replace("{t}", target))
    return "\n".join(f"- `{c}`" for c in combos) or "- _(관측된 서비스에 대한 조합 없음)_"


def generate_tistory(report, machine_name: str = "<머신명>",
                     attacker_ip: str | None = None) -> str:
    atk = attacker_ip or "<공격자 VPN IP>"
    os_class = report.profile.os_class.value if report.profile else "linux"
    os_line = f"{os_class} ({report.profile.tag})" if report.profile else "-"
    vuln_lines = []
    if report.detected_cve:
        vuln_lines.append(f"- 탐지 CVE: {', '.join(report.detected_cve)}")
    if report.detected_cwe:
        vuln_lines.append(f"- 탐지 CWE: {', '.join(report.detected_cwe)}")
    for m in report.vuln_matches:
        vuln_lines.append(f"- [{m.severity}] {m.name} ({' '.join(m.cve + m.cwe)}) — {m.note}")
    vuln_block = "\n".join(vuln_lines) or "_(명시적 CVE/CWE 미탐지)_"
    one_day_block = _one_day_block(report)

    return f"""# [{machine_name}] 보안 분석 — 포트부터 탐지까지

> 권한이 확인된 환경 대상. 플레이스홀더(`<...>`)는 실제 값으로 교체.

## 1. 개요
- 대상: {report.target} / OS: {os_line} / 공격자: {atk}
- 요약: 정찰→열거→취약점 분석→(침투)→블루팀 탐지 관점까지 정리.

## 2. 아키텍처 · 프로토콜 다이어그램
{_arch_diagram(report.host, report.target, atk)}

## 3. 포트 & 서비스 스캔
{_port_table(report.host) if report.host else "_(스캔 결과 없음)_"}

## 4. 공격 시나리오 요약
{_scenario_table(report)}

## 5. 정찰 명령 해설 (바이너리 / 옵션 / 파라미터)
{_cmd_explanations(report)}

## 6. 서비스별 열거
{_enum_section(report)}

## 7. 취약점 분석 (CVE / CWE)
{vuln_block}

### 1-day 메타데이터 후보
{one_day_block}

## 8. 고급 명령 조합 예시
{_advanced_combos(report.host, report.target)}

## 9. 내장 셸 명령 매핑 (Post-Exploitation Enumeration)
{_shell_cmd_map(os_class)}

## 10. 침투 / 권한 상승 (수동)
{chr(10).join('- ' + s for s in report.manual_suggestions) or "- _(수동 분석 필요)_"}

## 11. 블루팀 탐지 지표 (SIEM / IDS / 패킷)
{_blue_team(report.host)}

## 12. 완화 · 대응 방안
- 불필요한 포트/서비스 비활성화, 최신 패치 적용(위 CVE)
- 강력한 인증(키/MFA), 계정 잠금·로깅, 네트워크 세분화
- IDS/SIEM 룰 적용 및 정기 점검(위 탐지 지표)

## 13. 마무리 · 참고
- 체크리스트: 포트 열거 / 취약점 검증 / 침투 / 탐지·완화 정리 완료
- 본 글은 관측·사용자 자료 기반 자동 초안(htb-agent). 외부 라이트업 미참조.
"""
