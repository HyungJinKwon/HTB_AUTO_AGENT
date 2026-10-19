"""
Credential Vault — 자격증명 저장·재사용
=========================================

발견/제공된 자격증명을 저장하고, 지식베이스 제안 템플릿의 {user}/{pass}/{domain}/
{hash} 플레이스홀더를 채워 '수동 제안 → 자동 실행 후보'로 승격시킨다(승인 하).
침투 후 확보한 계정을 AD 단계로 이어가는 연결고리.

⚠️ 자격증명은 민감정보다. 상태 저장(state/)에는 복원 불가능한 메타데이터만 남기고,
감사 기록에서는 알려진 비밀값을 가린다. 로컬 권한 확인된 HTB 훈련 용도에 한정하며,
LLM 프롬프트에는 기본적으로 넣지 않는다.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

_LEFT = re.compile(r"\{[a-zA-Z_]+\}")
# 플레이스홀더 → Credential 속성
_FIELD = {"user": "username", "pass": "password", "domain": "domain",
          "hash": "nt_hash", "nthash": "nt_hash"}


@dataclass
class Credential:
    username: str
    password: str | None = None
    domain: str | None = None
    nt_hash: str | None = None
    source: str = "user"

    def to_dict(self) -> dict:
        return {"username": self.username, "password": self.password,
                "domain": self.domain, "nt_hash": self.nt_hash, "source": self.source}

    def to_public_dict(self) -> dict:
        """Resume/audit metadata only; passwords and hashes never reach state."""
        return {"username": self.username, "domain": self.domain, "source": self.source,
                "has_password": bool(self.password), "has_nt_hash": bool(self.nt_hash)}

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        return cls(username=d.get("username", ""), password=d.get("password"),
                   domain=d.get("domain"), nt_hash=d.get("nt_hash"),
                   source=d.get("source", "user"))

    def label(self) -> str:
        dom = f"{self.domain}/" if self.domain else ""
        secret = "****" if (self.password or self.nt_hash) else "(no-secret)"
        return f"{dom}{self.username}:{secret}"


def fill(template: str, target: str, cred: Credential) -> tuple[str, bool]:
    """템플릿의 {t} + 자격증명 플레이스홀더를 채운다. (cmd, 완전치환?) 반환."""
    values = {name: getattr(cred, attr) for name, attr in _FIELD.items()}
    values["t"] = target
    quote = ""
    out = []
    complete = True
    index = 0
    while index < len(template):
        match = _LEFT.match(template, index)
        if match:
            if quote:
                # User KB rules must keep credential placeholders outside quotes.
                complete = False
                out.append(match.group())
                index = match.end()
                continue
            value = values.get(match.group()[1:-1])
            if value is None:
                complete = False
                out.append(match.group())
            else:
                out.append(shlex.quote(value))
            index = match.end()
            continue
        char = template[index]
        if char == "\\" and quote != "'" and index + 1 < len(template):
            out.append(template[index:index + 2])
            index += 2
            continue
        if char in ("'", '"'):
            if quote == char:
                quote = ""
            elif not quote:
                quote = char
        out.append(char)
        index += 1
    return "".join(out), complete


class CredentialVault:
    def __init__(self, creds: list[Credential] | None = None):
        self.creds = creds if creds is not None else []

    def add(self, cred: Credential) -> None:
        # 중복(동일 user/pass/domain) 제거
        key = (cred.username, cred.password, cred.domain, cred.nt_hash)
        if key not in {(c.username, c.password, c.domain, c.nt_hash) for c in self.creds}:
            self.creds.append(cred)

    @classmethod
    def from_cli(cls, items: list[str] | None) -> "CredentialVault":
        """'user:pass' 또는 'user:pass:domain' 또는 'user' 형식 파싱."""
        vault = cls()
        for item in items or []:
            parts = item.split(":")
            username = parts[0]
            password = parts[1] if len(parts) > 1 and parts[1] != "" else None
            domain = parts[2] if len(parts) > 2 and parts[2] != "" else None
            if username:
                vault.add(Credential(username=username, password=password,
                                     domain=domain, source="cli"))
        return vault

    @classmethod
    def load_file(cls, path: str) -> "CredentialVault":
        """JSON object/list; invalid or unreadable input must not silently lose credentials."""
        vault = cls()
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as e:
            raise ValueError("자격증명 JSON 파일을 읽을 수 없습니다") from e
        rows = data if isinstance(data, list) else [data]
        if not rows:
            raise ValueError("자격증명 목록이 비어 있습니다")
        allowed = {"username", "password", "domain", "nt_hash", "source"}
        for d in rows:
            if (not isinstance(d, dict) or set(d) - allowed
                    or not isinstance(d.get("username"), str) or not d["username"].strip()
                    or any(v is not None and (not isinstance(v, str) or "\x00" in v)
                           for v in d.values())):
                raise ValueError("자격증명 형식 오류: username 및 문자열 필드가 필요합니다")
            vault.add(Credential.from_dict(d))
        return vault

    def expand(self, template: str, target: str,
               max_creds: int = 3) -> list[tuple[str, bool]]:
        """
        템플릿을 (명령, 실행가능여부) 목록으로 확장.
        - 자격증명 플레이스홀더가 없으면 → [(cmd, True)]
        - 있고 볼트에 자격증명이 있으면 → 채워진 명령들(runnable=True)
        - 있고 볼트가 비면 → [(원본, False)] (수동 제안으로 남김)
        """
        base = template.replace("{t}", target)
        if _LEFT.search(base) is None:
            return [(base, True)]
        if not self.creds:
            return [(base, False)]
        out: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for cred in self.creds[:max_creds]:
            cmd, filled = fill(template, target, cred)
            if filled and cmd not in seen:
                seen.add(cmd)
                out.append((cmd, True))
        return out or [(base, False)]

    def to_list(self) -> list[dict]:
        return [c.to_dict() for c in self.creds]

    def to_public_list(self) -> list[dict]:
        return [c.to_public_dict() for c in self.creds]

    def secret_values(self) -> list[str]:
        return [value for cred in self.creds
                for value in (cred.password, cred.nt_hash) if value]

    def redact(self, text: str) -> str:
        for secret in sorted(self.secret_values(), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        return text
