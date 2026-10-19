"""
Audit Log — 실행 트랜스크립트 (JSONL)
======================================

에이전트의 모든 결정·실행을 타임스탬프와 함께 JSONL 로 기록한다. 권한이 확인된
테스트의 '무엇을 언제 했는가'를 남겨 (1) 정당성 입증/감사, (2) 학습 복기,
(3) 라이트업 정확도에 쓴다.

주의: 기록에는 실행 명령이 포함되며, 자격증명이 명령 인자로 들어간 경우 민감정보가
남을 수 있다. 감사 파일은 state/ 아래(또는 지정 경로)에 저장되고 .gitignore 된다.
로컬·권한확인 HTB 용도에 한정한다.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class NullAudit:
    """비활성 감사(no-op). 인터페이스 동일."""
    path = None

    def event(self, etype: str, **data) -> None:
        pass

    def close(self) -> None:
        pass


class AuditLog:
    def __init__(self, path: str, secrets: list[str] | None = None):
        self.path = path
        self._secrets = tuple(sorted({s for s in (secrets or []) if s}, key=len, reverse=True))
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def event(self, etype: str, **data) -> None:
        rec = {"ts": _now(), "event": etype}
        rec.update(data)
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(self._redact(rec), ensure_ascii=False) + "\n")
        except OSError:
            pass  # 로깅 실패가 본 작업을 막지 않는다

    def close(self) -> None:
        self.event("session_end_marker")

    def add_secrets(self, secrets: list[str]) -> None:
        self._secrets = tuple(sorted({*self._secrets, *(s for s in secrets if s)},
                                     key=len, reverse=True))

    def _redact(self, value):
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact(item) for item in value)
        return value
