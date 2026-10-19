"""
clues — 환경 증거(Clue) 수집·누적
===================================

MazeRunner(2608.14216) 의 두 번째 병목 **Contextual Amnesia**(유한 컨텍스트가
긴 교전에서 단서를 잊음) 대응. 도구 출력에서 교차단계로 재사용될 '단서'를
뽑아 누적하고, LLM 후보 생성 컨텍스트에 되먹인다.

Clue 는 Finding(관측 사실)이나 Credential(자격증명)과 다른 가벼운 1차 증거다 —
"어디선가 본 사용자명/경로/호스트/해시". 무엇을 할지는 LLM 이 정하고, 여기서는
**놓치지 않게 모아두기만** 한다(자동 실행 없음).

ponytail: 파서 동물원을 만들지 않는다. observation/* 가 이미 nmap/smb/web 을
구조화하므로, 여기서는 그 위를 가로지르는 '관심 문자열' 몇 종류만 정규식으로.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# 종류별 추출 정규식. 과하게 잡지 않도록 경계를 둔다.
_PATTERNS: dict[str, re.Pattern] = {
    # AD/도메인 호스트명 (다중 라벨 FQDN 포함: dc01.corp.htb)
    "host": re.compile(r"\b(?:[a-z0-9][a-z0-9-]{0,61}\.)+(?:htb|local|lan|corp)\b", re.I),
    # 사용자명 단서 — 'user:', 'username=', smb/rid 열거 흔적
    "user": re.compile(r"(?:user(?:name)?\s*[:=]\s*|RID\s+\d+:\s*\S*\\)([A-Za-z][\w.-]{1,31})"),
    # 흥미로운 경로 (설정/백업/키/업로드)
    "path": re.compile(r"(?:/[\w.-]+)*/(?:[\w.-]*(?:config|backup|\.bak|id_rsa|\.kdbx|"
                       r"\.conf|upload|secret|cred)[\w.-]*)", re.I),
    # 해시 (NTLM/MD5 32hex, SHA 계열 앞부분)
    "hash": re.compile(r"\b[a-f0-9]{32}(?::[a-f0-9]{32})?\b", re.I),
    # 노출된 서비스/버전 배너 흔적 ("Apache/2.4.49", "OpenSSH 8.2")
    "software": re.compile(r"\b([A-Z][A-Za-z]{2,}[ /]\d+\.\d+(?:\.\d+)?)\b"),
}

# 플래그 형식(32hex)과 겹치는 흔한 오탐을 hash 에서 걸러낸다(플래그는 flag.py 담당).
_SKIP_HASH_CONTEXT = ("user.txt", "root.txt", "flag")


@dataclass
class ClueStore:
    """종류별 단서 집합(삽입순·중복제거). 상한으로 폭주를 막는다."""
    per_kind_cap: int = 40
    _kinds: dict[str, list[str]] = field(default_factory=dict)

    def add(self, kind: str, value: str) -> bool:
        value = value.strip()
        if not value:
            return False
        bucket = self._kinds.setdefault(kind, [])
        if value in bucket or len(bucket) >= self.per_kind_cap:
            return False
        bucket.append(value)
        return True

    def harvest(self, text: str) -> int:
        """텍스트 한 덩어리에서 모든 종류를 추출. 새로 추가된 단서 수 반환."""
        if not text:
            return 0
        added = 0
        for kind, pat in _PATTERNS.items():
            for m in pat.finditer(text):
                val = m.group(m.lastindex or 0)
                if kind == "hash" and any(h in text.lower() for h in _SKIP_HASH_CONTEXT):
                    continue      # 플래그 파일 맥락의 32hex 는 단서 아님(플래그다)
                if self.add(kind, val):
                    added += 1
        return added

    def kinds(self) -> dict[str, list[str]]:
        return {k: list(v) for k, v in self._kinds.items() if v}

    def context_lines(self, per_kind: int = 6) -> list[str]:
        """LLM 컨텍스트용 요약 — 종류별 상위 몇 개만."""
        out: list[str] = []
        for kind, vals in self._kinds.items():
            if vals:
                out.append(f"{kind}: " + ", ".join(vals[:per_kind]))
        return out

    def __bool__(self) -> bool:
        return any(self._kinds.values())
