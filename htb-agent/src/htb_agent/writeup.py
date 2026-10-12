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
from .enrich import CWE_NAMES, Enricher


def _cwe_label(cwe_id: str) -> str:
    """CWE ID 에 이름을 덧붙인다(가독성·§5). 미등재면 ID 만."""
    name = CWE_NAMES.get(cwe_id.upper(), "")
    return f"{cwe_id}({name})" if name else cwe_id


def _enriched_refs(report) -> str:
    """수집된 CVE 레퍼런스(NVD 설명·CVSS·PoC)를 출처와 함께 표기(§3·§5)."""
    enriched = getattr(report, "enriched", None) or []
    if not enriched:
        return "_(CVE 자동 수집 비활성/오프라인 또는 탐지 CVE 없음 — `--no-enrich`/`--offline` 확인)_"
    lines = []
    for e in enriched:
        head = f"- **{e.id}**"
        meta = []
        if e.severity:
            meta.append(e.severity)
        if e.cvss:
            meta.append(f"CVSS {e.cvss}")
        if meta:
            head += f" [{' · '.join(meta)}]"
        lines.append(head)
        if e.description:
            desc = e.description.strip().replace("\n", " ")
            lines.append(f"  - 설명: {desc[:240]}")
        if e.cwe:
            lines.append(f"  - CWE: {', '.join(_cwe_label(c) for c in e.cwe)}")
        if e.references:
            lines.append(f"  - 참조: {Enricher.cve_url(e.id)}")
            for r in e.references[:3]:
                lines.append(f"    - {r}")
        else:
            lines.append(f"  - 참조(NVD): {Enricher.cve_url(e.id)}")
        if e.poc_repos:
            lines.append(f"  - 공개 PoC: {', '.join(e.poc_repos[:3])}")
        lines.append(f"  - 출처: {e.source}")
    return "\n".join(lines)


def _flag_line(report, kind: str, fallback: str) -> str:
    """캡처된 플래그가 있으면 값, 없으면 안내 문구."""
    # CTF/Dreamhack(single) 는 user/root 구분이 없으므로 캡처된 플래그를 user 행에 표기
    if getattr(report, "flag_kind", "boot2root") == "single":
        if kind == "user":
            vals = [f.value for f in report.flags]
            return ("  ".join(f"`{v}`" for v in vals) + "  ✅ 획득") if vals \
                else f"미획득 ({fallback})"
        return "(Jeopardy — 단일 플래그, 상단 참조)"
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
    5986: {"svc": "WinRM/HTTPS", "siem": "Event 4624, WinRM 운영 로그(암호화)",
           "ids": 'alert tcp any any -> $HOME_NET 5986 (msg:"WinRM-S";)',
           "wireshark": "tls && tcp.port==5986", "check": "자격증명 재사용, 인증서 검증"},
    25: {"svc": "SMTP", "siem": "메일 로그: 비정상 RCPT/VRFY 급증",
         "ids": 'alert tcp any any -> $HOME_NET 25 (msg:"SMTP user enum (VRFY/EXPN)"; content:"VRFY";)',
         "wireshark": "smtp", "check": "VRFY/EXPN 사용자 열거, 오픈릴레이, 서비스 버전(Exim CVE)"},
    53: {"svc": "DNS", "siem": "DNS 쿼리 로그: AXFR 시도, 비정상 대량 쿼리",
         "ids": 'alert tcp any any -> $HOME_NET 53 (msg:"DNS zone transfer (AXFR)"; content:"|00 00 fc|";)',
         "wireshark": "dns", "check": "존 전송(AXFR) 허용, 서브도메인 열거"},
    110: {"svc": "POP3", "siem": "메일 로그: 로그인 실패/성공",
          "ids": 'alert tcp any any -> $HOME_NET 110 (msg:"POP3 login";)',
          "wireshark": "pop", "check": "평문 자격증명, 무차별 대입"},
    143: {"svc": "IMAP", "siem": "메일 로그: 로그인 실패/성공",
          "ids": 'alert tcp any any -> $HOME_NET 143 (msg:"IMAP login";)',
          "wireshark": "imap", "check": "평문 자격증명, 무차별 대입"},
    111: {"svc": "RPCbind", "siem": "RPC 포트매퍼 조회 로그",
          "ids": 'alert tcp any any -> $HOME_NET 111 (msg:"RPC portmapper dump";)',
          "wireshark": "portmap || rpc", "check": "rpcinfo 노출, NFS 공유(2049) 연계"},
    2049: {"svc": "NFS", "siem": "NFS mount/export 접근 로그",
           "ids": 'alert tcp any any -> $HOME_NET 2049 (msg:"NFS access";)',
           "wireshark": "nfs || mount", "check": "no_root_squash, 세계쓰기 export, showmount -e"},
    135: {"svc": "MSRPC", "siem": "Event 5156(WFP), RPC 엔드포인트 조회",
          "ids": 'alert tcp any any -> $HOME_NET 135 (msg:"MSRPC endpoint mapper";)',
          "wireshark": "dcerpc || epm", "check": "RPC 엔드포인트 열거, PetitPotam/인증강제"},
    161: {"svc": "SNMP", "siem": "SNMP 접근 로그: 기본 커뮤니티 스트링",
          "ids": 'alert udp any any -> $HOME_NET 161 (msg:"SNMP public community"; content:"public";)',
          "wireshark": "snmp", "check": "기본 커뮤니티(public/private), v1/v2c 평문, snmpwalk 노출"},
    636: {"svc": "LDAPS", "siem": "Event 2889, DC 로그(암호화 바인드)",
          "ids": 'alert tcp any any -> $HOME_NET 636 (msg:"LDAPS query";)',
          "wireshark": "tls && tcp.port==636", "check": "익명 바인드, 인증서, 채널바인딩"},
    1433: {"svc": "MSSQL", "siem": "SQL Server 로그인 감사, Event 33205",
           "ids": 'alert tcp any any -> $HOME_NET 1433 (msg:"MSSQL login";)',
           "wireshark": "tds", "check": "sa 약한 암호, xp_cmdshell, 링크드서버, 무차별 대입"},
    3306: {"svc": "MySQL/MariaDB", "siem": "general_log/감사 플러그인 로그인",
           "ids": 'alert tcp any any -> $HOME_NET 3306 (msg:"MySQL login";)',
           "wireshark": "mysql", "check": "root 약한 암호, 원격 접속 허용, UDF 권한상승"},
    5432: {"svc": "PostgreSQL", "siem": "pg_log 로그인 실패/성공",
           "ids": 'alert tcp any any -> $HOME_NET 5432 (msg:"PostgreSQL login";)',
           "wireshark": "pgsql", "check": "postgres 약한 암호, COPY TO/FROM PROGRAM RCE"},
    6379: {"svc": "Redis", "siem": "비인증 접근 로그, 비정상 CONFIG/SAVE",
           "ids": 'alert tcp any any -> $HOME_NET 6379 (msg:"Redis unauth"; content:"PING";)',
           "wireshark": "redis || tcp.port==6379", "check": "비인증 접근, CONFIG SET으로 키/웹셸/SSH키 기록"},
    27017: {"svc": "MongoDB", "siem": "비인증 접근 로그",
            "ids": 'alert tcp any any -> $HOME_NET 27017 (msg:"MongoDB access";)',
            "wireshark": "mongo || tcp.port==27017", "check": "비인증 접근, 기본 바인드 노출"},
    8080: {"svc": "HTTP-alt", "siem": "웹 access.log 비정상 경로/상태코드",
           "ids": 'alert http any any -> $HOME_NET 8080 (msg:"HTTP-alt dir brute"; threshold:type threshold,track by_src,count 50,seconds 10;)',
           "wireshark": "http.request && tcp.port==8080", "check": "관리 콘솔(Tomcat/Jenkins), 디렉토리 브루트포싱"},
}


def _port_table(host) -> str:
    rows = ["| 포트 | 프로토콜 | 서비스 | 버전/배너 |", "|---|---|---|---|"]
    for p in host.ports:
        if p.state == "open":
            rows.append(f"| {p.port} | {p.proto} | {p.service or '-'} | {p.banner or '-'} |")
    if len(rows) == 2:
        rows.append("| - | - | (열린 포트 없음) | - |")
    return "\n".join(rows)


def _revshell_block(report) -> str:
    """자동 준비된 리버스쉘 페이로드를 라이트업 침투 섹션에 삽입(생성 전용)."""
    shells = getattr(report, "revshells", None)
    if not shells:
        return ""
    from .revshell import listener_hints
    lines = ["", f"**리버스쉘 (자동 준비 · LHOST={report.revshell_lhost} "
             f"LPORT={report.revshell_lport} · 생성만, 권한 확인 대상에서 직접 실행):**", ""]
    lines.append(f"- 리스너: `{listener_hints(report.revshell_lport)[0]}`")
    for s in shells:
        lines.append(f"- {s.name}: `{s.payload}`")
    return "\n".join(lines)


def _crack_block(report) -> str:
    """자동 준비된 해시 크래킹 작업을 라이트업에 삽입(생성 전용)."""
    jobs = getattr(report, "crack_jobs", None)
    if not jobs:
        return ""
    lines = ["", "**해시 크래킹 (자동 준비 · 생성만, 사용자 환경에서 실행):**", ""]
    for j in jobs:
        gnames = ", ".join(g.name for g in j.guesses) or "미상"
        lines.append(f"- 해시 `{j.hash[:48]}{'…' if len(j.hash) > 48 else ''}` — 식별: {gnames}")
        for c in j.commands:
            lines.append(f"    - [{c.tool}] `{c.command}`")
    return "\n".join(lines)


def _privesc_block(report) -> str:
    """자동 준비된 권한상승 플레이북을 라이트업에 삽입(생성 전용)."""
    steps = getattr(report, "privesc_steps", None)
    if not steps:
        return "- _(수동 분석: SUID/sudo, 커널, 서비스 오구성, AD 공격경로 등)_"
    lines = ["", "**권한상승 플레이북 (자동 준비 · 대상 셸에서 실행 · 생성만):**", ""]
    for s in steps:
        note = f"  — {s.note}" if s.note else ""
        lines.append(f"- [{s.category}] `{s.command}`{note}")
    cands = getattr(report, "privesc_cve_candidates", [])
    if cands:
        lines.append("")
        lines.append("**LPE CVE 후보:**")
        for c in cands:
            lines.append(f"- {c}")
    return "\n".join(lines)


def _analysis_block(report) -> str:
    """LLM 분석가(B3) 판단을 라이트업에 삽입(가설·경로·집중·확신도)."""
    text = getattr(report, "analysis", "")
    plan = getattr(report, "plan", None)
    out = ""
    if plan:
        board = "\n".join("- " + ln for ln in plan.board_lines())
        out += ("\n**가설 보드 (분석가가 세우고 결과로 갱신 — 방향 잡기용〔추정〕):**\n\n"
                + board + "\n")
    if text:
        body = "\n".join("> " + ln for ln in text.splitlines() if ln.strip())
        out += "\n**분석 (LLM — 가설·공격경로·집중):**\n\n" + body + "\n"
    return out


def _cloud_block(report) -> str:
    """자동 준비된 AWS/S3 열거(버킷 후보+점검)를 라이트업에 삽입(생성 전용)."""
    checks = getattr(report, "cloud_checks", None)
    if not checks:
        return ""
    cands = getattr(report, "cloud_candidates", [])
    lines = ["", "**AWS/S3 열거 (자동 준비 · 생성만, AWS 는 범위 밖·직접 실행):**", ""]
    if cands:
        lines.append(f"- 버킷 후보({len(cands)}): " + ", ".join(f"`{c}`" for c in cands[:12])
                     + (" …" if len(cands) > 12 else ""))
    for c in checks:
        lines.append(f"- {c.name}: `{c.command}`")
    return "\n".join(lines)


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


def _defense_mirror(report) -> str:
    """취약점별 탐지·완화 미러(공격↔방어) + 배포형 탐지 산출물(Sigma/Suricata/Navigator/MISP/
    triage). defense·detections 모듈에 위임(생성 전용)."""
    from . import defense, detections
    mirror = defense.render_markdown(report)
    deploy = detections.render_markdown(report)
    return mirror + "\n\n**배포형 탐지 산출물** (ARTEX detections 식 — 검증 후 사용):\n\n" + deploy


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
        vuln_lines.append(f"- 탐지 CWE: {', '.join(_cwe_label(c) for c in report.detected_cwe)}")
    for m in report.vuln_matches:
        sev = f"[{m.severity}] " if m.severity else ""
        ids = " ".join(m.cve + [_cwe_label(c) for c in m.cwe])
        vuln_lines.append(f"- {sev}**{m.name}** ({ids}) — {m.note}")
        for s in m.suggest:
            vuln_lines.append(f"  - 제안: `{s}`")
    vuln_block = "\n".join(vuln_lines) or "_(명시적 CVE/CWE 미탐지 — 수동 분석 필요)_"

    foothold = []
    for m in report.vuln_matches:
        for s in m.suggest:
            foothold.append(f"- `{s}`  (취약점: {m.name})")
    for s in report.manual_suggestions:
        foothold.append(f"- {s}")
    foothold_block = "\n".join(foothold) or "- _(수동 분석 필요)_"
    foothold_block += _revshell_block(report)
    foothold_block += _cloud_block(report)
    foothold_block += _crack_block(report)

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
{_analysis_block(report)}

## 3. 취약점 분석 (Vulnerability Analysis)

{vuln_block}

### 3.1 CVE 레퍼런스 (공식 출처 자동 수집 — NVD/PoC)

{_enriched_refs(report)}

## 4. 공격 시나리오 요약

{_scenario_table(report)}

## 5. 초기 침투 (Foothold)

{foothold_block}

- user.txt: {_flag_line(report, "user", username)}

## 6. 권한 상승 (Privilege Escalation)
{_privesc_block(report)}
- root.txt: {_flag_line(report, "root", "관리자 권한 획득 후")}

## 7. 블루팀 탐지 지표 (Blue Team)

### 7.1 포트 기준 탐지 지표
{_blue_team(report.host)}

### 7.2 취약점별 탐지·완화 미러 (공격↔방어)
{_defense_mirror(report)}

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
    if any(p in ports for p in (389, 636)):
        combos.append("ldapsearch -x -H ldap://{t} -b 'DC=domain,DC=local' '(objectClass=user)'".replace("{t}", target))
    if 161 in ports:
        combos.append("snmpwalk -v2c -c public {t} | tee snmp.txt".replace("{t}", target))
        combos.append("onesixtyone -c community.txt {t}".replace("{t}", target))
    if 1433 in ports:
        combos.append("impacket-mssqlclient DOMAIN/user:pass@{t} -windows-auth".replace("{t}", target))
    if 3306 in ports:
        combos.append("mysql -h {t} -u root -p --ssl=0".replace("{t}", target))
    if 6379 in ports:
        combos.append("redis-cli -h {t} INFO; redis-cli -h {t} CONFIG GET dir".replace("{t}", target))
    if any(p in ports for p in (111, 2049)):
        combos.append("showmount -e {t}".replace("{t}", target))
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
        vuln_lines.append(f"- 탐지 CWE: {', '.join(_cwe_label(c) for c in report.detected_cwe)}")
    for m in report.vuln_matches:
        ids = " ".join(m.cve + [_cwe_label(c) for c in m.cwe])
        vuln_lines.append(f"- [{m.severity}] {m.name} ({ids}) — {m.note}")
    vuln_block = "\n".join(vuln_lines) or "_(명시적 CVE/CWE 미탐지)_"

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
{_analysis_block(report)}

## 5. 정찰 명령 해설 (바이너리 / 옵션 / 파라미터)
{_cmd_explanations(report)}

## 6. 서비스별 열거
{_enum_section(report)}

## 7. 취약점 분석 (CVE / CWE)
{vuln_block}

### 7.1 CVE 레퍼런스 (NVD/PoC 자동 수집)
{_enriched_refs(report)}

## 8. 고급 명령 조합 예시
{_advanced_combos(report.host, report.target)}

## 9. 내장 셸 명령 매핑 (Post-Exploitation Enumeration)
{_shell_cmd_map(os_class)}

## 10. 침투 / 권한 상승 (수동)
{(chr(10).join('- ' + s for s in report.manual_suggestions) or "- _(수동 분석 필요)_") + _revshell_block(report) + _cloud_block(report) + _crack_block(report) + _privesc_block(report)}

## 11. 블루팀 탐지 지표 (SIEM / IDS / 패킷)
{_blue_team(report.host)}

## 12. 완화 · 대응 방안

### 12.1 취약점별 탐지·완화 미러 (공격↔방어)
{_defense_mirror(report)}

### 12.2 공통 하드닝
- 불필요한 포트/서비스 비활성화, 최신 패치 적용(위 CVE)
- 강력한 인증(키/MFA), 계정 잠금·로깅, 네트워크 세분화
- IDS/SIEM 룰 적용 및 정기 점검(위 탐지 지표)

## 13. 마무리 · 참고
- 체크리스트: 포트 열거 / 취약점 검증 / 침투 / 탐지·완화 정리 완료
- 본 글은 관측·사용자 자료 기반 자동 초안(htb-agent). 외부 라이트업 미참조.
"""
