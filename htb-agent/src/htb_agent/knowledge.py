"""
Knowledge Base — 사용자 제공 학습데이터로 '성장'하는 지식
=========================================================

에이전트는 외부 라이트업을 검색하지 않는다(P1). 대신 **사용자가 직접 제공한**
규칙/노트를 지식베이스(KB)에 누적하고, 관측(OS·포트·서비스)에 맞는 다음 액션을
제안한다. 파일을 추가할수록 제안이 풍부해진다 = '성장'.

구성:
  - 내장 시드 규칙(SEED_RULES): 표준 도구 사용 템플릿(라이트업 아님).
  - 사용자 규칙:  <knowledge>/rules/*.json   (아래 스키마)
  - 사용자 노트:  <knowledge>/notes/**/*.md|.txt (하위 디렉토리 포함, 자유 서술, 맥락 제공)

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

# KB 스키마/콘텐츠 세대 — 공유 시드 동기화 호환 판정·진단 표시용(G4). 규칙 스키마나 시드
# 포맷이 바뀌면 올린다. kb_sync 는 이 값을 메타에 기록해, 세대가 다른 캐시는 무시(fail-safe).
KB_VERSION = "1"


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
        self.warnings: list[str] = []   # 로드 중 건너뛴 파일·항목, 쓰이지 않는 규칙 등

    @classmethod
    def load(cls, base_dir: str | None = None, include_seeds: bool = True) -> "KnowledgeBase":
        rules: list[Rule] = list(SEED_RULES) if include_seeds else []
        notes: list[str] = []
        warnings: list[str] = []
        if base_dir and os.path.isdir(base_dir):
            rules += _load_rule_dir(os.path.join(base_dir, "rules"), warnings)
            from .kb_sync import active_overlays  # 공유 저장소 최신 시드(검증된 로컬 캐시)
            notes += _load_notes_dir(os.path.join(base_dir, "notes"),
                                     overlays=active_overlays(base_dir))
        kb = cls(rules, notes)
        kb.warnings = warnings
        return kb

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

    def _lowered_notes(self) -> list[str]:
        """노트 소문자 사본 캐시. RAG 는 라운드마다 호출되므로 매번 수백 KB 를
        lower() 하지 않는다. 시그니처는 '모든 노트의 id 튜플' — 추가·교체·중간 원소 치환까지
        감지한다(감사 A-LOW8: 과거 (len, id(notes[-1])) 는 마지막이 아닌 원소 교체 시 stale).
        id() 호출만 하므로 lower() 대비 무시 가능한 비용."""
        cache = getattr(self, "_lower_cache", None)
        sig = tuple(id(n) for n in self.notes)
        if cache is None or cache[0] != sig:
            cache = (sig, [n.lower() for n in self.notes])
            self._lower_cache = cache
        return cache[1]

    def _tfidf_index(self):
        """노트 코퍼스의 TF-IDF 색인 캐시. RAG 는 단계×라운드×스윕마다 호출되므로, 같은 노트
        집합에 대해 색인(df/idf/norm — 전 코퍼스 토크나이즈)을 매번 재구성하지 않는다. 시그니처는
        `_lowered_notes` 와 동일한 '노트 id 튜플'이라 추가·교체 시 자동 무효화(항상 최신·결정적)."""
        from .tfidf import TfidfIndex
        cache = getattr(self, "_tfidf_cache", None)
        sig = tuple(id(n) for n in self.notes)
        if cache is None or cache[0] != sig:
            cache = (sig, TfidfIndex(self._lowered_notes()))
            self._tfidf_cache = cache
        return cache[1]

    def external_notes(self) -> list[str]:
        """런타임에 '외부에서 가져온' 노트(자가학습·웹학습: 파일명이 learned…)의 본문.
        provenance 의 looked-up 판정용 — 번들 시드(seed-…, 공략 흔적 없는 레퍼런스)는 제외한다.
        노트 문자열은 '[파일명] 본문' 형식으로 저장된다."""
        out: list[str] = []
        for n in self.notes:
            if n.startswith("[learned"):   # learned-*, learned-web-* (자가/웹 학습)
                body = n.split("]", 1)[1] if "]" in n else n
                out.append(body)
        return out

    def relevant_notes(self, terms: list[str], limit: int = 3) -> list[str]:
        """[T2-c] 경량 RAG: 쿼리 용어와 노트의 관련도 랭킹 상위 N개. 노트가 2개 이상이면
        TF-IDF 코사인(희귀 용어 가중·길이 정규화 — tfidf.py, stdlib)으로, 그 외엔 키워드
        겹침 개수로 점수화한다. 매칭이 전혀 없으면 기존처럼 앞 N개로 폴백(동작 보존)."""
        if not self.notes:
            return []
        q = [t.lower() for t in terms if t and len(t) >= 2]
        if not q:
            return self.notes[:limit]
        if len(self.notes) >= 2:
            # 색인은 노트 집합별로 캐시(_tfidf_index) — 매 호출 재구성 않고도 내용 교체/추가 시 최신.
            ranked = self._tfidf_index().rank(q, limit=limit)
            if ranked:
                return [self.notes[i] for i, _ in ranked]
            return self.notes[:limit]
        # 노트 1개 — 키워드 겹침(TF-IDF 는 df 가 degenerate)
        low = self._lowered_notes()[0]
        return [self.notes[0]] if any(t in low for t in q) else self.notes[:limit]


_VALID_PHASES = {"enum", "access", "privesc", "lateral"}
_VALID_OS = {"linux", "windows", "windows_ad", "unknown"}


def _load_rule_dir(path: str, warnings: list[str] | None = None) -> list[Rule]:
    """규칙 디렉터리 로드. 문제 있는 파일·항목은 건너뛰되 사유를 warnings 에 남긴다
    (이전엔 조용히 사라지거나, 포트 값 하나가 잘못되면 전체 로드가 예외로 중단됐다)."""
    warn = warnings.append if warnings is not None else (lambda _m: None)
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
        except (OSError, ValueError) as e:   # ValueError ⊃ JSONDecodeError·UnicodeDecodeError
            warn(f"{fn}: 읽기/JSON 파싱 실패로 파일 전체 건너뜀 ({e})")
            continue
        items = data if isinstance(data, list) else [data]
        for i, it in enumerate(items):
            if not isinstance(it, dict) or "name" not in it or "suggest" not in it:
                warn(f"{fn}#{i}: name/suggest 없는 항목 건너뜀")
                continue
            name = str(it["name"])
            sug = it["suggest"]
            if not isinstance(sug, list):
                warn(f"{fn}: '{name}' suggest 가 목록이 아님 — 건너뜀")
                continue
            when = it.get("when", {}) or {}
            if not isinstance(when, dict):
                warn(f"{fn}: '{name}' when 이 매핑이 아님 — 건너뜀")
                continue
            try:
                ports = [int(p) for p in when.get("ports", [])]
            except (TypeError, ValueError):
                warn(f"{fn}: '{name}' 포트 값이 정수가 아님 — 건너뜀")
                continue
            phase = str(it.get("phase", "enum"))
            if phase not in _VALID_PHASES:
                warn(f"{fn}: '{name}' 알 수 없는 phase {phase!r} — 어떤 단계에도 매칭 안 됨")
            bad_os = [o for o in when.get("os", []) if o not in _VALID_OS]
            if bad_os:
                warn(f"{fn}: '{name}' 알 수 없는 os {bad_os} — 해당 값은 매칭 안 됨")
            if not (when.get("os") or ports or when.get("services")):
                warn(f"{fn}: '{name}' when 조건 없음 — query 에서 반환되지 않음(보존)")
            out.append(Rule(
                name=name,
                suggest=[str(x) for x in sug],
                os=list(when.get("os", [])),
                ports=ports,
                services=list(when.get("services", [])),
                note=str(it.get("note", "")),
                source=f"user:{fn}",
                tags=list(it.get("tags", [])),
                phase=phase,
            ))
    return out


# 노트 1개당 RAG 반영 문자 상한. '완성형' 심화 시드(종합 레퍼런스)가 실제로
# 활용되도록 충분히 크게 둔다(기존 500자는 심화 지식을 잘라 깊이를 무력화했음).
# 상위 N개만 프롬프트에 주입되므로(relevant_notes limit) 컨텍스트 폭증 없음.
NOTE_CHARS = 6000


def _load_notes_dir(path: str, overlays: dict[str, str] | None = None) -> list[str]:
    # 하위 디렉토리(예: notes/learned/ — 자가학습 노트)까지 포함해 '성장'을 반영.
    # overlays: notes/learned/ 의 번들 시드 대신 읽을 파일 {파일명: 경로}(kb_sync 캐시).
    out: list[str] = []
    if not os.path.isdir(path):
        return out
    learned = os.path.normpath(os.path.join(path, "learned"))
    for root, dirs, files in os.walk(path):
        dirs.sort()   # 파일시스템과 무관하게 노트 순서를 결정적으로(RAG 동점 순위 안정)
        for fn in sorted(files):
            # 폴더 안내문(README)은 노트가 아니다 — 관련 노트가 없을 때 기본값으로 LLM 에 주입되던 문제
            if fn.lower() in ("readme.md", "readme.txt"):
                continue
            if fn.endswith((".md", ".txt")):
                src = os.path.join(root, fn)
                if overlays and fn in overlays and os.path.normpath(root) == learned:
                    src = overlays[fn]
                try:
                    with open(src, encoding="utf-8", errors="replace") as f:   # 비UTF-8 노트도 로드
                        out.append(f"[{fn}] " + f.read().strip()[:NOTE_CHARS])
                except OSError:
                    continue
    return out
