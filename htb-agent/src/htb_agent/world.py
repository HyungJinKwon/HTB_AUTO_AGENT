"""
World Model — 구조화된 공격 상태 (파이프라인·LLM·리포트의 단일 상태원)
======================================================================

정찰·열거·침투 과정에서 드러난 사실을 **구조화된 상태**로 축적한다. 지금까지
평면적 findings 리스트(명령→요약문자열)에 흩어져 있던 정보를 한곳에 모아:

  - 각 단계가 읽고 쓰는 단일 상태(hosts/services/creds/loot/flags/vulns/access)
  - LLM 에 깔끔한 상태 컨텍스트 제공(원시 로그 대신 정돈된 사실)
  - 리포트/요약/JSON 의 일관된 출처

이 모듈은 상태 '표현'만 담당한다(실행·판단 없음). 반복·재진입 흐름(A1)·분석가
역할(B3)이 이 상태를 토대로 올라간다. 전부 표준 라이브러리만.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 획득 권한 레벨(낮음→높음). raise_access 가 항상 최고치를 유지한다.
ACCESS_ORDER: dict[str, int] = {
    "none": 0, "credentialed": 1, "user": 2, "root": 3,
}


def _more_specific_version(new: str, old: str) -> bool:
    """`new` 가 `old` 를 '대체할 만큼 더 구체적'이면 True. 멀쩡한 값을 무관한 값으로 덮지 않도록
    보수적: 기존이 비었거나 / 기존이 새 값의 점표기 접두(예: old=16, new=16.0.40.7)일 때만 True.
    역방향(16.0.40.7 → 16)·무관한 값은 False(기존 유지)."""
    new = (new or "").strip()
    old = (old or "").strip()
    if not new or new == old:
        return False
    if not old:
        return True
    no, oo = new.split("."), old.split(".")
    return len(no) > len(oo) and no[:len(oo)] == oo   # old 가 new 의 점표기 접두


@dataclass
class ServiceEntry:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""

    def label(self) -> str:
        v = " ".join(x for x in (self.product, self.version) if x)
        return f"{self.port}/{self.proto} {self.name or '?'}" + (f" ({v})" if v else "")


@dataclass
class WorldModel:
    target: str
    hostname: str = ""
    os_class: str = "unknown"
    os_confidence: float = 0.0
    is_dc: bool = False
    services: list[ServiceEntry] = field(default_factory=list)
    creds: list[str] = field(default_factory=list)        # "user:pass" / "user:<hash>"
    loot: list[str] = field(default_factory=list)          # 해시·민감파일·노출정보
    learned: list[str] = field(default_factory=list)       # 자율학습 지식(수집물 아님 — 측면이동 수단으로 치지 않음)
    flags: dict[str, str] = field(default_factory=dict)    # kind(user/root/..) -> value
    proven_vulns: list[str] = field(default_factory=list)  # CVE/CWE(+근거)
    evidence: dict = field(default_factory=dict)           # 사실(크리덴셜/수집물/취약점) → 출처(어느 명령에서 나왔나)
    access_level: str = "none"
    web_product: str = ""   # 관측된 웹앱 제품키(예: freepbx) — searchsploit {product} 치환
    web_version: str = ""   # 관측된 웹앱 버전(예: 15.0) — searchsploit {version} 치환

    # ── 쓰기(갱신) ──
    def set_profile(self, host, prof) -> None:
        """nmap 호스트 + 프로파일 결과로 호스트/서비스 상태를 채운다."""
        if prof is not None:
            self.os_class = prof.os_class.value
            self.os_confidence = prof.confidence
            self.is_dc = prof.is_domain_controller
        if host is None:
            return
        for p in host.ports:
            if p.state == "open":
                self.add_service(p.port, getattr(p, "proto", "tcp"),
                                 p.service or "", getattr(p, "product", "") or "",
                                 getattr(p, "version", "") or "")

    def set_web_app(self, product: str, version: str = "") -> None:
        """관측된 웹앱 제품/버전을 기록. 제품은 처음 식별값을 유지하되, 버전은 **더 구체적인
        값(기존을 점표기 접두로 포함)으로 보강**한다(docstring 과 코드 일치). 과거의 write-once
        고착(빈/거친 버전이 고정돼 정확한 값으로 못 바뀌던 버그) 교정."""
        if product and not self.web_product:
            self.web_product = product
        if product and product == self.web_product and version:
            if _more_specific_version(version, self.web_version):
                self.web_version = version

    def add_service(self, port: int, proto: str = "tcp", name: str = "",
                    product: str = "", version: str = "") -> None:
        for s in self.services:
            if s.port == port and s.proto == proto:
                # 더 풍부한 정보로 보강
                s.name = s.name or name
                s.product = s.product or product
                s.version = s.version or version
                return
        self.services.append(ServiceEntry(port, proto, name, product, version))

    def add_cred(self, cred: str, source: str = "") -> None:
        cred = (cred or "").strip()
        if cred and cred not in self.creds:
            self.creds.append(cred)
            self.raise_access("credentialed")
        if cred and source:
            self.evidence.setdefault(cred, source)   # 교육: 이 사실을 '어떻게 알았는지'

    def add_loot(self, item: str, source: str = "") -> None:
        item = (item or "").strip()
        if item and item not in self.loot:
            self.loot.append(item)
        if item and source:
            self.evidence.setdefault(item, source)

    def add_learned(self, item: str, source: str = "") -> None:
        """자율학습으로 얻은 지식. loot 과 분리한다 — 학습 토픽은 '측면이동 수단'이
        아니므로 lateral 전제조건(bool(loot))을 충족시키면 안 된다(상태 오염 방지)."""
        item = (item or "").strip()
        if item and item not in self.learned:
            self.learned.append(item)
        if item and source:
            self.evidence.setdefault(item, source)

    def add_flag(self, kind: str, value: str) -> None:
        if value and self.flags.get(kind) != value:
            self.flags[kind] = value
        if kind == "user":
            self.raise_access("user")
        elif kind == "root":
            self.raise_access("root")

    def add_vuln(self, entry: str, source: str = "") -> None:
        entry = (entry or "").strip()
        if entry and entry not in self.proven_vulns:
            self.proven_vulns.append(entry)
        if entry and source:
            self.evidence.setdefault(entry, source)

    def raise_access(self, level: str) -> None:
        """현재보다 높은 권한 레벨일 때만 올린다(되돌아가지 않음)."""
        if ACCESS_ORDER.get(level, 0) > ACCESS_ORDER.get(self.access_level, 0):
            self.access_level = level

    def has_access(self, level: str) -> bool:
        return ACCESS_ORDER.get(self.access_level, 0) >= ACCESS_ORDER.get(level, 0)

    # ── 읽기(표현) ──
    def context_lines(self) -> list[str]:
        """LLM 컨텍스트용 정돈된 상태 요약(원시 로그 대신)."""
        out = [f"OS={self.os_class}(확신 {self.os_confidence:.0%})"
               + (" DC" if self.is_dc else "") + f", 권한레벨={self.access_level}"]
        if self.services:
            out.append("서비스: " + ", ".join(s.label() for s in self.services))
        if self.creds:
            out.append(f"보유 크리덴셜 {len(self.creds)}건: "
                       + ", ".join(self._with_src(c) for c in self.creds[:5]))
        if self.loot:
            out.append("수집물: " + "; ".join(self.loot[:5]))
        if self.learned:
            out.append("학습한 지식: " + "; ".join(self.learned[:5]))
        if self.proven_vulns:
            out.append("확인 취약점: " + ", ".join(self.proven_vulns[:6]))
        if self.flags:
            out.append("플래그: " + ", ".join(f"{k}={'O' if v else 'X'}"
                                             for k, v in self.flags.items()))
        return out

    def _with_src(self, fact: str) -> str:
        """사실에 출처가 있으면 '사실 (출처: ...)' 로 — '왜 아는지'를 보여준다(교육)."""
        src = self.evidence.get(fact)
        return f"{fact} (출처: {src})" if src else fact

    def summary(self) -> str:
        from . import ui
        lines = [ui.kv("권한레벨", ui.accent2(self.access_level), 9),
                 ui.kv("OS", f"{self.os_class} ({self.os_confidence:.0%})"
                       + (" · DC" if self.is_dc else ""), 9),
                 ui.kv("서비스", str(len(self.services)) + "개", 9)]
        if self.creds:
            lines.append(ui.kv("크리덴셜", str(len(self.creds)) + "건", 9))
        if self.loot:
            lines.append(ui.kv("수집물", str(len(self.loot)) + "건", 9))
        if self.proven_vulns:
            lines.append(ui.kv("취약점", ", ".join(self.proven_vulns[:5]), 9))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "os_class": self.os_class,
            "os_confidence": self.os_confidence,
            "is_dc": self.is_dc,
            "access_level": self.access_level,
            "web_product": self.web_product,   # [S5-4] 리포트 내보내기·완전성용
            "web_version": self.web_version,
            "services": [{"port": s.port, "proto": s.proto, "name": s.name,
                          "product": s.product, "version": s.version}
                         for s in self.services],
            "creds": list(self.creds),
            "loot": list(self.loot),
            "flags": dict(self.flags),
            "proven_vulns": list(self.proven_vulns),
            "evidence": dict(self.evidence),
        }
