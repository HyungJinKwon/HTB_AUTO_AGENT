"""
Knowledge Base — 사용자 제공 학습데이터로 '성장'하는 지식
=========================================================

에이전트는 외부 라이트업을 검색하지 않는다(P1). 대신 **사용자가 직접 제공한**
규칙/노트를 지식베이스(KB)에 누적하고, 관측(OS·포트·서비스)에 맞는 다음 액션을
제안한다. 파일을 추가할수록 제안이 풍부해진다 = '성장'.

구성:
  - 내장 시드 규칙(SEED_RULES): 표준 도구 사용 템플릿(라이트업 아님).
  - 사용자 규칙:  <knowledge>/rules/*.json   (아래 스키마)
  - 사용자 노트:  <knowledge>/notes/*.md     (자유 서술, 맥락 제공)

규칙 JSON 스키마(한 파일에 객체 1개 또는 배열):
  {
    "name": "AD DC 수집",
    "when": {"os": ["windows_ad"], "ports": [88,389], "services": ["ldap"]},
    "suggest": ["bloodhound-python -d {domain} -u {user} -p {pass} -ns {t} -c all"],
    "note": "도메인 크리덴셜 확보 후 실행",
    "tags": ["ad","bloodhound"]
  }

템플릿 플레이스홀더:
  {t} = 타겟 IP(자동 치환). {domain}/{user}/{pass} 등 그 외 값은 '수동' 제안으로
  분류되어 자동 실행되지 않는다(크리덴셜 등 민감값 자동실행 방지).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field


@dataclass
class Rule:
    name: str
    suggest: list[str]
    os: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    note: str = ""
    source: str = "builtin"
    tags: list[str] = field(default_factory=list)
    phase: str = "enum"   # 모의해킹 단계: enum / access / privesc / lateral


@dataclass
class Recommendation:
    rule_name: str
    source: str
    suggestions: list[str]
    note: str
    score: int
    tags: list[str] = field(default_factory=list)
    phase: str = "enum"


# 표준 도구 사용 템플릿(일반 지식 — 특정 머신 라이트업 아님)
SEED_RULES: list[Rule] = [
    Rule("웹 기초 열거", ["curl -i http://{t}/", "whatweb http://{t}"],
         ports=[80, 8080], services=["http"], tags=["web"],
         note="상태/헤더/기술스택 파악"),
    Rule("웹 디렉토리 탐색",
         ["gobuster dir -u http://{t} -w /usr/share/seclists/Discovery/Web-Content/common.txt"],
         ports=[80, 8080, 443], services=["http"], tags=["web"]),
    Rule("HTTPS 기초", ["curl -ik https://{t}/"], ports=[443], services=["https"], tags=["web"]),
    Rule("FTP 익명 확인", ["curl ftp://{t}/ --user anonymous:anonymous"],
         ports=[21], services=["ftp"], tags=["ftp"]),
    Rule("SMB 열거(인증없음)", ["netexec smb {t}", "enum4linux-ng {t}", "smbclient -L //{t}/ -N"],
         ports=[139, 445], services=["smb", "microsoft-ds", "netbios"], tags=["smb"]),
    Rule("LDAP 익명 베이스", ["ldapsearch -x -H ldap://{t} -s base namingcontexts"],
         ports=[389], services=["ldap"], os=["windows_ad"], tags=["ad", "ldap"]),
    Rule("AD 유저 열거(AS-REP)", ["kerbrute userenum -d {domain} --dc {t} {userlist}"],
         ports=[88], services=["kerberos"], os=["windows_ad"], tags=["ad"],
         note="도메인/유저리스트 필요(수동)"),
    Rule("AD BloodHound 수집",
         ["bloodhound-python -d {domain} -u {user} -p {pass} -ns {t} -c all"],
         ports=[389, 88], os=["windows_ad"], tags=["ad", "bloodhound"],
         note="도메인 크리덴셜 확보 후(수동)", phase="access"),
    Rule("WinRM 셸", ["evil-winrm -i {t} -u {user} -p {pass}"],
         ports=[5985, 5986], services=["winrm"], os=["windows", "windows_ad"],
         tags=["ad", "shell"], note="크리덴셜 필요(수동)", phase="access"),
    Rule("SSH 접속", ["ssh {user}@{t}"], ports=[22], services=["ssh"], tags=["linux"],
         note="크리덴셜/키 필요(수동)", phase="access"),
    # ── 플래그 획득 (자격증명 확보 시 볼트로 승격) ──
    Rule("유저 플래그(Windows/WinRM)",
         ['netexec winrm {t} -u {user} -p {pass} -x "type C:\\Users\\{user}\\Desktop\\user.txt"'],
         ports=[5985, 5986], os=["windows", "windows_ad"], phase="access",
         tags=["flag"], note="user.txt"),
    Rule("유저 플래그(Linux/SSH)",
         ['sshpass -p {pass} ssh -o StrictHostKeyChecking=no {user}@{t} "cat ~/user.txt; id"'],
         ports=[22], os=["linux"], phase="access", tags=["flag"], note="user.txt"),
    Rule("루트 플래그(Windows)",
         ['netexec smb {t} -u {user} -p {pass} -x "type C:\\Users\\Administrator\\Desktop\\root.txt"'],
         ports=[445], os=["windows", "windows_ad"], phase="privesc",
         tags=["flag"], note="root.txt (관리자 권한 필요)"),
    Rule("루트 플래그(Linux)",
         ['sshpass -p {pass} ssh -o StrictHostKeyChecking=no {user}@{t} "sudo -n cat /root/root.txt"'],
         ports=[22], os=["linux"], phase="privesc", tags=["flag"],
         note="root.txt (sudo/root 권한 필요)"),
]

_PLACEHOLDER = re.compile(r"\{[a-zA-Z_]+\}")


class KnowledgeBase:
    def __init__(self, rules: list[Rule] | None = None, notes: list[str] | None = None):
        self.rules = rules if rules is not None else []
        self.notes = notes if notes is not None else []

    @classmethod
    def load(cls, base_dir: str | None = None, include_seeds: bool = True) -> "KnowledgeBase":
        rules: list[Rule] = list(SEED_RULES) if include_seeds else []
        notes: list[str] = []
        if base_dir and os.path.isdir(base_dir):
            rules += _load_rule_dir(os.path.join(base_dir, "rules"))
            notes += _load_notes_dir(os.path.join(base_dir, "notes"))
        return cls(rules, notes)

    def query(self, os_class: str, open_ports: list[int],
              services: list[str] | None = None,
              phase: str | None = None) -> list[Recommendation]:
        services = [s.lower() for s in (services or [])]
        ports = set(open_ports)
        recs: list[Recommendation] = []
        for r in self.rules:
            # 단계 필터: 지정됐는데 불일치면 제외
            if phase is not None and r.phase != phase:
                continue
            # OS 제약: 지정됐는데 불일치면 제외
            if r.os and os_class not in r.os:
                continue
            port_spec = bool(r.ports)
            svc_spec = bool(r.services)
            port_match = (not port_spec) or bool(ports & set(r.ports))
            svc_match = (not svc_spec) or any(
                rs in sv for rs in r.services for sv in services
            )
            # 포트/서비스 제약이 있으면 둘 중 지정된 것은 맞아야 함
            if port_spec and not port_match:
                continue
            if svc_spec and not svc_match:
                continue
            # 아무 제약도 없고 OS도 없으면 너무 일반적 → 제외
            if not (r.os or port_spec or svc_spec):
                continue
            score = (2 if (r.os and os_class in r.os) else 0) \
                + (2 if (port_spec and port_match) else 0) \
                + (1 if (svc_spec and svc_match) else 0)
            recs.append(Recommendation(r.name, r.source, list(r.suggest),
                                       r.note, score, list(r.tags), r.phase))
        recs.sort(key=lambda x: x.score, reverse=True)
        return recs

    def format_suggestion(self, template: str, target: str) -> tuple[str, bool]:
        """{t} 치환. 남은 플레이스홀더가 있으면 '수동'(auto_runnable=False)."""
        cmd = template.replace("{t}", target)
        auto_runnable = _PLACEHOLDER.search(cmd) is None
        return cmd, auto_runnable


def _load_rule_dir(path: str) -> list[Rule]:
    out: list[Rule] = []
    if not os.path.isdir(path):
        return out
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".json"):
            continue
        fp = os.path.join(path, fn)
        try:
            with open(fp, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        items = data if isinstance(data, list) else [data]
        for it in items:
            if not isinstance(it, dict) or "name" not in it or "suggest" not in it:
                continue
            when = it.get("when", {}) or {}
            out.append(Rule(
                name=str(it["name"]),
                suggest=list(it["suggest"]),
                os=list(when.get("os", [])),
                ports=[int(p) for p in when.get("ports", [])],
                services=list(when.get("services", [])),
                note=str(it.get("note", "")),
                source=f"user:{fn}",
                tags=list(it.get("tags", [])),
                phase=str(it.get("phase", "enum")),
            ))
    return out


def _load_notes_dir(path: str) -> list[str]:
    out: list[str] = []
    if not os.path.isdir(path):
        return out
    for fn in sorted(os.listdir(path)):
        # README(폴더 사용법 안내)와 `_` 접두 파일(예시·초안)은 노트가 아니다 — 읽으면
        # 안내문이 매 LLM 호출에 '사용자 노하우'로 주입되어 토큰만 태운다.
        if fn.upper().startswith("README") or fn.startswith("_"):
            continue
        if fn.endswith((".md", ".txt")):
            try:
                with open(os.path.join(path, fn), encoding="utf-8") as f:
                    out.append(f"[{fn}] " + f.read().strip()[:500])
            except OSError:
                continue
    return out
