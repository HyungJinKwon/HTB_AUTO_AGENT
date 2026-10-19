"""
Session State — 진행 상태 영속화 (중단/재개)
=============================================

오케스트레이션 진행 상태를 JSON 으로 저장·복원한다. 긴 머신을 여러 세션에
걸쳐 이어서 진행할 수 있고, 재개 시 이미 파악한 포트(RECON)를 재사용해
재스캔을 건너뛴다.

state.py 는 순수 데이터 계층(오케스트레이터를 임포트하지 않는다 → 순환 방지).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .observation.parsers import NmapHost, Port


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── NmapHost <-> dict ────────────────────────────────────────────────
def host_to_dict(host: NmapHost) -> dict:
    return {
        "address": host.address,
        "state": host.state,
        "hostscripts": dict(host.hostscripts),
        "ports": [
            {"port": p.port, "proto": p.proto, "state": p.state, "service": p.service,
             "product": p.product, "version": p.version, "extrainfo": p.extrainfo,
             "scripts": dict(p.scripts)}
            for p in host.ports
        ],
    }


def host_from_dict(d: dict) -> NmapHost:
    host = NmapHost(address=d.get("address", ""), state=d.get("state", "unknown"),
                    hostscripts=dict(d.get("hostscripts", {})))
    for pd in d.get("ports", []):
        host.ports.append(Port(
            port=int(pd.get("port", 0)), proto=pd.get("proto", "tcp"),
            state=pd.get("state", ""), service=pd.get("service", ""),
            product=pd.get("product", ""), version=pd.get("version", ""),
            extrainfo=pd.get("extrainfo", ""), scripts=dict(pd.get("scripts", {})),
        ))
    return host


# ── 세션 상태 ────────────────────────────────────────────────────────
@dataclass
class SessionState:
    target: str
    allowed_ranges: list[str] = field(default_factory=list)
    attacker_ips: list[str] = field(default_factory=list)
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)
    recon_status: str = ""
    host: dict | None = None
    profile: dict | None = None
    enum_findings: list[dict] = field(default_factory=list)
    llm_findings: list[dict] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    detected_cve: list[str] = field(default_factory=list)
    detected_cwe: list[str] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        known = {f: d.get(f) for f in cls.__dataclass_fields__ if f in d}
        return cls(**known)

    def add_history(self, event: str) -> None:
        self.history.append({"time": _now(), "event": event})

    def summary(self) -> str:
        lines = [f"# 저장된 세션 — {self.target} (업데이트 {self.updated})",
                 f"  RECON: {self.recon_status or '-'}"]
        if self.host:
            open_ports = [p["port"] for p in self.host.get("ports", []) if p.get("state") == "open"]
            lines.append(f"  열린 포트: {open_ports}")
        if self.profile:
            lines.append(f"  OS: {self.profile.get('os_class')} "
                         f"(확신도 {self.profile.get('confidence')})")
        lines.append(f"  enum {len(self.enum_findings)}건, LLM {len(self.llm_findings)}건, "
                     f"수동 {len(self.manual_suggestions)}건, 이력 {len(self.history)}건")
        return "\n".join(lines)


# ── 저장소 ───────────────────────────────────────────────────────────
class StateStore:
    def __init__(self, base_dir: str = "state"):
        self.base_dir = base_dir

    @staticmethod
    def _safe(target: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", target)

    def path_for(self, target: str) -> str:
        return os.path.join(self.base_dir, self._safe(target) + ".json")

    def exists(self, target: str) -> bool:
        return os.path.isfile(self.path_for(target))

    def save(self, state: SessionState) -> str:
        os.makedirs(self.base_dir, exist_ok=True)
        path = self.path_for(state.target)
        state.updated = _now()
        with open(path, "w", encoding="utf-8") as f:
            f.write(state.to_json())
        return path

    def load(self, target: str) -> SessionState | None:
        path = self.path_for(target)
        try:
            with open(path, encoding="utf-8") as f:
                return SessionState.from_dict(json.load(f))
        except (OSError, json.JSONDecodeError):
            return None

    def list_targets(self) -> list[str]:
        if not os.path.isdir(self.base_dir):
            return []
        return [fn[:-5] for fn in sorted(os.listdir(self.base_dir)) if fn.endswith(".json")]
