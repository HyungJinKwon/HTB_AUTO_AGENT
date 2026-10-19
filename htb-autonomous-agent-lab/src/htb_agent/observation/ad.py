"""
AD/LDAP Enum Parsers — ldapsearch 출력 구조화
==============================================

ldapsearch 의 LDIF 출력을 파싱해 namingContexts(도메인 베이스), 엔트리(dn)
목록을 추출한다. AD 대상에서 도메인 구조·계정 열거의 근거가 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LdapResult:
    naming_contexts: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    domain_functionality: str = ""
    parse_error: str = ""

    @property
    def entries(self) -> int:
        return len(self.dns)

    def summary(self, top: int = 6) -> str:
        if not (self.naming_contexts or self.dns):
            return "ldap: 결과 없음" + (f" ({self.parse_error})" if self.parse_error else "")
        parts = []
        if self.naming_contexts:
            parts.append("베이스: " + ", ".join(self.naming_contexts))
        if self.domain_functionality:
            parts.append(f"기능수준={self.domain_functionality}")
        if self.dns:
            shown = "; ".join(self.dns[:top])
            more = f" …(+{len(self.dns) - top})" if len(self.dns) > top else ""
            parts.append(f"엔트리 {len(self.dns)}건: {shown}{more}")
        return "ldap: " + " | ".join(parts)


def parse_ldapsearch(text: str) -> LdapResult:
    res = LdapResult()
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("#") or not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        # LDIF base64 값(::)은 앞의 ':' 제거 후 그대로
        value = value.lstrip(":").strip()
        if key == "namingcontexts":
            res.naming_contexts.append(value)
        elif key == "dn" and value:   # rootDSE 의 빈 dn 은 제외
            res.dns.append(value)
        elif key in ("domainfunctionality", "forestfunctionality"):
            res.domain_functionality = value
    return res
