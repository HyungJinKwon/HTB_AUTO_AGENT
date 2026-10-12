"""
배포형 탐지 산출물 — '돌려볼 수 있는' 블루팀 룰셋 생성 (ARTEX detections/ 아이디어, 클린룸)
================================================================================================

`defense.py` 가 '취약점→탐지/완화'를 **산문 표**로 만든다면, 이 모듈은 한 걸음 더 나아가
실제 배포 가능한 산출물을 **문자열로 생성**한다(생성 전용 — 실행·설치 없음):

  · **Sigma** 룰(YAML)         — SIEM 범용 탐지(로그 소스 비의존).
  · **Suricata** 룰             — 네트워크 IDS(HTTP 페이로드 패턴).
  · **ATT&CK Navigator** layer  — 매핑된 기법을 색칠한 layer JSON.
  · **MISP** 지표(IoC) 이벤트   — 관측 대상·탐지 CVE 를 방어 지표로.
  · **host-triage** 스크립트    — 읽기 전용 침해 분류 셸(수집만, 변경 없음).

안전·정직성(§3/§4/§7):
  · 근거 있는 것만 — 탐지·공략된 CWE/CVE·대상에서만 생성(지어내지 않음).
  · 방어용·읽기 전용 — triage 는 조회 명령만(변경·공격 없음). 전부 문자열 생성.
  · 대상 IP 는 '권한 확인된 CTF 자산'의 방어 지표로만 포함(외부 전송 없음).
"""
from __future__ import annotations

import json

# CWE → (ATT&CK 기법 ID, 이름). 매핑 없으면 공개 서비스 익스플로잇 포괄 기법으로.
_CWE_ATTACK: dict[str, tuple[str, str]] = {
    "CWE-89":  ("T1190", "Exploit Public-Facing Application"),
    "CWE-78":  ("T1059", "Command and Scripting Interpreter"),
    "CWE-79":  ("T1059.007", "JavaScript"),
    "CWE-22":  ("T1083", "File and Directory Discovery"),
    "CWE-434": ("T1505.003", "Web Shell"),
    "CWE-98":  ("T1190", "Exploit Public-Facing Application"),
    "CWE-287": ("T1078", "Valid Accounts"),
    "CWE-288": ("T1078", "Valid Accounts"),
    "CWE-200": ("T1595", "Active Scanning"),
    "CWE-862": ("T1190", "Exploit Public-Facing Application"),
    "CWE-502": ("T1190", "Exploit Public-Facing Application"),
    "CWE-918": ("T1190", "Exploit Public-Facing Application"),
    "CWE-362": ("T1190", "Exploit Public-Facing Application"),
}

# CWE → (Sigma 제목, HTTP 페이로드 키워드들). 웹서버 접근로그 범용 탐지.
_CWE_SIGMA: dict[str, tuple[str, tuple[str, ...]]] = {
    "CWE-89":  ("Possible SQL Injection in HTTP request",
                ("union select", "' or '1'='1", "sleep(", "benchmark(", "information_schema")),
    "CWE-78":  ("Possible OS Command Injection in HTTP request",
                (";id", "|id", "$(", "`id`", ";nc ", "|nc ", "wget http", "curl http")),
    "CWE-79":  ("Possible XSS payload in HTTP request",
                ("<script", "onerror=", "onload=", "javascript:", "alert(")),
    "CWE-22":  ("Possible Path Traversal in HTTP request",
                ("../", "..%2f", "%2e%2e", "/etc/passwd", "....//")),
    "CWE-434": ("Possible malicious file upload",
                (".php", ".phtml", ".jsp", ".asp", "multipart/form-data")),
    "CWE-98":  ("Possible Remote File Inclusion",
                ("php://", "data://", "http://", "https://", "expect://")),
    "CWE-287": ("Repeated authentication failures then success",
                ("login", "authenticate", "wp-login", "admin")),
    "CWE-918": ("Possible SSRF to internal/metadata endpoint",
                ("169.254.169.254", "localhost", "127.0.0.1", "metadata")),
}

# 네트워크로 의미 있는 CWE 만 Suricata 규칙 생성(HTTP content 매칭).
_CWE_SURICATA: dict[str, tuple[str, tuple[str, ...]]] = {
    "CWE-89":  ("SQLi UNION/boolean pattern", ("union select", "' or '1'='1")),
    "CWE-78":  ("OS command injection pattern", (";id", "$(", "|nc ")),
    "CWE-22":  ("Path traversal pattern", ("../", "/etc/passwd")),
    "CWE-918": ("SSRF to cloud metadata", ("169.254.169.254",)),
}


def _cwes(report) -> list[str]:
    out: list[str] = []
    for c in (getattr(report, "detected_cwe", []) or []):
        cu = str(c).upper()
        if cu not in out:
            out.append(cu)
    for m in (getattr(report, "vuln_matches", []) or []):
        for c in (getattr(m, "cwe", []) or []):
            cu = str(c).upper()
            if cu not in out:
                out.append(cu)
    return out


def _cves(report) -> list[str]:
    seen: list[str] = []
    for c in (list(getattr(report, "detected_cve", []) or [])
              + list(getattr(report, "discovered_cve", []) or [])):
        if c and c not in seen:
            seen.append(c)
    return seen


def attack_techniques(report) -> list[tuple[str, str, str]]:
    """(기법 ID, 이름, 근거 CWE) 목록 — 중복 기법 제거(첫 근거 CWE 유지)."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for cwe in _cwes(report):
        tech = _CWE_ATTACK.get(cwe)
        if tech and tech[0] not in seen:
            seen.add(tech[0])
            out.append((tech[0], tech[1], cwe))
    return out


def _sigma_yaml(title: str, cwe: str, keywords: tuple[str, ...]) -> str:
    tech = _CWE_ATTACK.get(cwe, ("", ""))
    kw = "\n".join(f"      - '{k}'" for k in keywords)
    tags = f"attack.{tech[0].lower()}" if tech[0] else "attack.t1190"
    return (
        f"title: {title}\n"
        f"id: assassin-{cwe.lower().replace('cwe-', 'cwe')}\n"
        f"status: experimental\n"
        f"description: ASSASSIN 자동 생성 — 탐지/공략된 {cwe} 에 대응(검증 후 운영 적용)\n"
        f"logsource:\n  category: webserver\n"
        f"detection:\n  selection:\n    c-uri|contains:\n{kw}\n"
        f"  condition: selection\n"
        f"level: high\n"
        f"tags:\n  - {tags}\n  - {cwe.lower()}\n"
    )


def sigma_rules(report) -> list[str]:
    return [_sigma_yaml(_CWE_SIGMA[cwe][0], cwe, _CWE_SIGMA[cwe][1])
            for cwe in _cwes(report) if cwe in _CWE_SIGMA]


def suricata_rules(report) -> list[str]:
    """HTTP content 매칭 Suricata 규칙. sid 는 로컬 범위(1000000+)."""
    rules: list[str] = []
    sid = 1000001
    for cwe in _cwes(report):
        sig = _CWE_SURICATA.get(cwe)
        if not sig:
            continue
        msg, keys = sig
        content = "".join(f' content:"{k}"; nocase;' for k in keys)
        rules.append(
            f'alert http any any -> $HOME_NET any (msg:"ASSASSIN {cwe} {msg}";'
            f' flow:established,to_server; http.uri;{content}'
            f' classtype:web-application-attack; sid:{sid}; rev:1;)')
        sid += 1
    return rules


def navigator_layer(report) -> dict:
    """ATT&CK Navigator layer(JSON 직렬화 가능 dict). 매핑된 기법을 색칠."""
    techs = attack_techniques(report)
    return {
        "name": f"ASSASSIN — {getattr(report, 'target', '')}",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "ASSASSIN 자동 생성 — 탐지/공략된 기법(검증 후 사용)",
        "techniques": [
            {"techniqueID": tid, "score": 100, "color": "#e60d0d",
             "comment": f"근거 {cwe} ({name})", "enabled": True}
            for (tid, name, cwe) in techs
        ],
        "gradient": {"colors": ["#ffffff", "#e60d0d"], "minValue": 0, "maxValue": 100},
    }


def misp_event(report) -> dict:
    """MISP 이벤트 유사 dict(방어 지표). 대상(권한 확인 CTF 자산)·탐지 CVE 를 IoC 로."""
    target = getattr(report, "target", "") or ""
    attrs: list[dict] = []
    if target:
        attrs.append({"type": "ip-dst", "category": "Network activity",
                      "value": target, "to_ids": False,
                      "comment": "권한 확인된 CTF 대상(방어 지표 — 외부 공유 금지)"})
    for cve in _cves(report):
        attrs.append({"type": "vulnerability", "category": "External analysis",
                      "value": cve, "to_ids": False})
    return {"Event": {"info": f"ASSASSIN detections — {target}",
                      "threat_level_id": "4", "analysis": "0",
                      "distribution": "0", "Attribute": attrs}}


def host_triage_script(report) -> str:
    """읽기 전용 침해 분류(triage) 셸 — 조회만(변경·공격 없음). 블루팀이 피해 호스트에서 실행."""
    return (
        "#!/usr/bin/env bash\n"
        "# ASSASSIN host-triage (읽기 전용 — 수집만, 변경/공격 없음). 검토 후 사용.\n"
        "set -u\n"
        'echo \"== identity ==\"; id; uname -a\n'
        'echo \"== listening sockets ==\"; ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null\n'
        'echo \"== processes ==\"; ps aux --sort=-%cpu | head -30\n'
        'echo \"== sudo rights ==\"; sudo -n -l 2>/dev/null\n'
        'echo \"== SUID files ==\"; find / -perm -4000 -type f 2>/dev/null | head -50\n'
        'echo \"== cron ==\"; crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null\n'
        'echo \"== recent logins ==\"; last -n 20 2>/dev/null\n'
        'echo \"== world-writable in web roots ==\"; '
        'find /var/www /srv -writable -type f 2>/dev/null | head -30\n'
    )


def has_content(report) -> bool:
    return bool(_cwes(report) or _cves(report) or getattr(report, "target", ""))


def render_markdown(report) -> str:
    """배포형 탐지 산출물을 Markdown(펜스 코드블록)으로. 근거 없으면 정직하게 생략 안내."""
    cwes = _cwes(report)
    if not cwes and not _cves(report):
        return ("_(탐지/공략된 CWE·CVE 가 없어 배포형 룰 생략 — 취약점 식별 시 "
                "Sigma/Suricata/Navigator/MISP 자동 생성)_")
    out: list[str] = []
    sigs = sigma_rules(report)
    if sigs:
        out.append("**Sigma 룰** (SIEM — 검증 후 적용):")
        out.append("```yaml\n" + "\n---\n".join(sigs) + "```")
    sur = suricata_rules(report)
    if sur:
        out.append("**Suricata 룰** (네트워크 IDS):")
        out.append("```\n" + "\n".join(sur) + "\n```")
    techs = attack_techniques(report)
    if techs:
        out.append("**ATT&CK 매핑**: "
                   + ", ".join(f"{t} ({n}, {c})" for t, n, c in techs))
        out.append("ATT&CK Navigator layer (JSON):")
        out.append("```json\n" + json.dumps(navigator_layer(report),
                                             ensure_ascii=False, indent=2) + "\n```")
    out.append("MISP 지표(IoC) — 방어용, 외부 공유 금지:")
    out.append("```json\n" + json.dumps(misp_event(report),
                                         ensure_ascii=False, indent=2) + "\n```")
    out.append("호스트 침해 분류(triage) — 읽기 전용:")
    out.append("```bash\n" + host_triage_script(report) + "```")
    return "\n\n".join(out)
