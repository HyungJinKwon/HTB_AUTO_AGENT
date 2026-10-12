"""
Report Export — 세션 결과를 구조화 포맷으로 내보내기
=====================================================

OrchestrationReport 를 (1) 기계판독 JSON 과 (2) 자체완결 HTML 대시보드로 변환한다.
순수 표준 라이브러리만 사용하고 네트워크를 쓰지 않는다. 외부 도구/파이프라인 연계와
가독성(§6 블루/네이비)을 위한 산출물이다.

  - to_dict(report)  : 직렬화 가능한 dict (안정적 스키마, schema_version 포함)
  - to_json(report)  : UTF-8 JSON 문자열(한글 보존)
  - to_html(report)  : 인라인 CSS HTML(외부 의존 0, 블루/네이비)

HTML 은 사용자 제공 값/배너를 그대로 렌더링하므로 반드시 escape 한다(XSS/깨짐 방지).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import recommend as _recommend
from .enrich import CWE_NAMES, Enricher

SCHEMA_VERSION = "1.9"   # 1.1~1.7 생략 / 1.8: discovered_cve / 1.9: world.learned export(SSOT 완전성)


# ──────────────────────────────────────────────────────────────────────
# 직렬화 (dict / JSON)
# ──────────────────────────────────────────────────────────────────────
def _port_dict(p) -> dict:
    return {
        "port": p.port, "proto": p.proto, "state": p.state,
        "service": p.service or "", "product": p.product or "",
        "version": p.version or "", "banner": p.banner,
    }


def _finding_dict(f) -> dict:
    return {"command": f.command, "ran": f.ran, "phase": f.phase,
            "note": f.note, "output": f.output}


def _vuln_dict(m) -> dict:
    return {"name": m.name, "cve": list(m.cve), "cwe": list(m.cwe),
            "severity": m.severity, "note": m.note, "matched_on": m.matched_on,
            "suggest": list(m.suggest), "source": m.source}


def _cve_dict(e) -> dict:
    return {"id": e.id, "description": e.description, "cvss": e.cvss,
            "severity": e.severity, "cwe": list(e.cwe),
            "references": list(e.references), "poc_repos": list(e.poc_repos),
            "source": e.source}


def to_dict(report) -> dict:
    """OrchestrationReport → 직렬화 가능한 dict(안정 스키마)."""
    host = report.host
    prof = report.profile
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "ASSASSIN",
        "target": report.target,
        "status": report.status,
        "message": report.message,
        "flag_kind": report.flag_kind,
        "os": {
            "class": prof.os_class.value if prof else "unknown",
            "tag": prof.tag if prof else "",
            "confidence": prof.confidence if prof else 0,
            "is_domain_controller": prof.is_domain_controller if prof else False,
        },
        "world": report.world.to_dict() if getattr(report, "world", None) else None,
        "analysis": getattr(report, "analysis", ""),
        # 가설 기록(계획 원장): 가설별 상태·확인 방법·기대 신호·시도·근거 — 방향 잡기용〔추정〕
        "plan": report.plan.to_dict() if getattr(report, "plan", None) else None,
        "phase_status": dict(getattr(report, "phase_status", {}) or {}),
        "goal_reached": bool(getattr(report, "goal_reached", False)),
        "llm_routing": dict(getattr(report, "llm_routing", {}) or {}),
        "timed_out": bool(getattr(report, "timed_out", False)),
        "elapsed_sec": float(getattr(report, "elapsed_sec", 0.0) or 0.0),
        "cost_capped": bool(getattr(report, "cost_capped", False)),
        "gate_stats": dict(getattr(report, "gate_stats", {}) or {}),
        "open_ports": host.open_ports if host else [],
        "ports": [_port_dict(p) for p in host.ports] if host else [],
        "enum_findings": [_finding_dict(f) for f in report.enum_findings],
        "llm_findings": [_finding_dict(f) for f in report.llm_findings],
        "detected_cve": list(report.detected_cve),
        "discovered_cve": list(report.discovered_cve),
        "detected_cwe": list(report.detected_cwe),
        "vuln_matches": [_vuln_dict(m) for m in report.vuln_matches],
        "enriched": [_cve_dict(e) for e in report.enriched],
        "flags": [{"value": f.value, "kind": f.kind, "source": f.source}
                  for f in report.flags],
        "user_flag": report.user_flag,
        "root_flag": report.root_flag,
        "manual_suggestions": list(report.manual_suggestions),
        "revshell": {
            "lhost": getattr(report, "revshell_lhost", ""),
            "lport": getattr(report, "revshell_lport", 0),
            "payloads": [{"name": s.name, "payload": s.payload}
                         for s in getattr(report, "revshells", [])],
        },
        "cloud": {
            "candidates": list(getattr(report, "cloud_candidates", [])),
            "checks": [{"name": c.name, "command": c.command}
                       for c in getattr(report, "cloud_checks", [])],
        },
        "privesc": {
            "steps": [{"category": s.category, "command": s.command, "note": s.note}
                      for s in getattr(report, "privesc_steps", [])],
            "cve_candidates": list(getattr(report, "privesc_cve_candidates", [])),
        },
        "crack": [
            {"hash": j.hash,
             "guesses": [{"name": g.name, "hashcat_mode": g.hashcat_mode,
                          "john_format": g.john_format} for g in j.guesses],
             "commands": [{"tool": c.tool, "name": c.name, "command": c.command}
                          for c in j.commands]}
            for j in getattr(report, "crack_jobs", [])
        ],
        "lateral": [
            {"technique": c.technique, "service": c.service,
             "command": c.command, "why": c.why}
            for c in getattr(report, "lateral_candidates", [])
        ],
        # 트레이스 기반 보고·평가(텍스트 요약과 동일 정보의 구조화 버전)
        "blockers": [
            {"command": cmd, "category": d.category, "label": d.label,
             "is_target": d.is_target, "kind": d.kind, "hint": d.hint}
            for cmd, d in getattr(report, "blockers", []) or []
        ],
        "flag_provenance": [
            {"kind": p.kind, "value": p.value, "command": p.command,
             "phase": p.phase, "verdict": p.verdict, "label": p.label, "reason": p.reason}
            for p in getattr(report, "flag_provenance", []) or []
        ],
        # [A6] LLM-심판(조언) — 있을 때만(opt-in). 규칙 판정과 독립된 보조 의견.
        "judge_verdict": (
            {"score": _jv.score, "passed": _jv.passed, "rationale": _jv.rationale}
            if (_jv := getattr(report, "judge_verdict", None)) is not None else None
        ),
        "learn": {
            "acquired": list(getattr(report, "acquired_knowledge", [])),
            "gaps": list(getattr(report, "knowledge_gaps", [])),
        },
        "knowledge": dict(getattr(report, "knowledge", {}) or {}),
        "next_options": [
            {"title": r.title, "rationale": r.rationale, "source": r.source, "ref": r.ref}
            for r in _recommend.propose(report).items
        ],
    }


def to_json(report, indent: int = 2) -> str:
    return json.dumps(to_dict(report), ensure_ascii=False, indent=indent)


# ──────────────────────────────────────────────────────────────────────
# HTML 대시보드 (블루/네이비 · 인라인 CSS · 외부 의존 0)
# ──────────────────────────────────────────────────────────────────────
_CSS = """
:root{--bg:#0b1220;--panel:#111c31;--panel2:#16233c;--line:#26406b;}
*{box-sizing:border-box}
body{margin:0;background:#0b1220;color:#dce6f5;font:14px/1.6 -apple-system,
 "Segoe UI",Roboto,"Noto Sans KR",sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px;color:#7fb4ff}
h2{font-size:16px;margin:26px 0 10px;color:#9ec5ff;border-bottom:1px solid #26406b;
 padding-bottom:6px}
.sub{color:#8aa0bf;font-size:13px;margin-bottom:18px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;
 font-weight:600;margin-right:6px}
.b-done{background:#133a2a;color:#5fe0a8}.b-info{background:#102a4d;color:#7fb4ff}
.b-crit{background:#3a1320;color:#ff8da3}.b-high{background:#3a2713;color:#ffc27f}
.b-med{background:#2a2a13;color:#e8e07f}.b-low{background:#16233c;color:#9ec5ff}
.panel{background:#111c31;border:1px solid #26406b;border-radius:10px;
 padding:14px 16px;margin:10px 0}
table{width:100%;border-collapse:collapse;margin:6px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #223a63}
th{color:#9ec5ff;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
code{background:#0b1626;color:#bfe0ff;padding:1px 6px;border-radius:5px;
 font:13px/1.5 "JetBrains Mono",Consolas,monospace;overflow-wrap:anywhere;word-break:break-all}
.flag{color:#5fe0a8;font-weight:700}
pre{background:#0b1626;color:#dce6f5;border:1px solid #223a63;border-radius:8px;padding:12px;
 white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 "JetBrains Mono",Consolas,monospace}
.muted{color:#8aa0bf}
a{color:#7fb4ff}
ul{margin:6px 0;padding-left:20px}
.kcol{color:#9ec5ff;width:120px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;
 margin:8px 0 4px}
.tile{background:#16233c;border:1px solid #26406b;border-radius:10px;padding:10px 12px}
.tile .num{font-size:24px;font-weight:700;color:#7fb4ff;line-height:1.2}
.tile .lbl{font-size:12px;color:#8aa0bf}
.tile.warn .num{color:#ffc27f}.tile.ok .num{color:#5fe0a8}
.checks{list-style:none;padding-left:0}.checks li{margin:4px 0}
.checks li::before{content:"✔ ";color:#5fe0a8;font-weight:700}
.foot{margin-top:28px;color:#6880a0;font-size:12px;border-top:1px solid #26406b;
 padding-top:12px}
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _link(url) -> str:
    """http(s) 주소만 링크로, 그 외(javascript: 등)는 글자로만 표시."""
    u = str(url or "")
    if u.lower().startswith(("http://", "https://")):
        return f"<a href='{_esc(u)}'>{_esc(u)}</a>"
    return _esc(u)


def _sev_class(sev: str) -> str:
    return {"critical": "b-crit", "high": "b-high",
            "medium": "b-med"}.get((sev or "").lower(), "b-low")


def _cwe_label(cwe_id: str) -> str:
    name = CWE_NAMES.get(cwe_id.upper(), "")
    return f"{cwe_id} ({name})" if name else cwe_id


def _cwe_link(cwe_id: str) -> str:
    """HTML: CWE 라벨을 MITRE 정의 페이지로 링크(사람이 바로 참조)."""
    return f"<a href='{_esc(Enricher.cwe_url(cwe_id))}'>{_esc(_cwe_label(cwe_id))}</a>"


def _html_ports(host) -> str:
    if not host or not host.open_ports:
        return "<p class='muted'>열린 포트 없음</p>"
    rows = ["<tr><th>포트</th><th>프로토콜</th><th>서비스</th><th>버전/배너</th></tr>"]
    for p in host.ports:
        if p.state == "open":
            rows.append(f"<tr><td><code>{p.port}</code></td><td>{_esc(p.proto)}</td>"
                        f"<td>{_esc(p.service or '-')}</td><td>{_esc(p.banner or '-')}</td></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _html_vulns(report) -> str:
    if not (report.vuln_matches or report.detected_cve or report.detected_cwe):
        return "<p class='muted'>명시적 CVE/CWE 미탐지 — 수동 분석 필요</p>"
    out = []
    if report.detected_cve:
        out.append("<p><b>탐지 CVE</b>: " +
                   ", ".join(f"<code>{_esc(c)}</code>" for c in report.detected_cve) + "</p>")
    if report.detected_cwe:
        out.append("<p><b>탐지 CWE</b>: " +
                   ", ".join(_cwe_link(c) for c in report.detected_cwe) + "</p>")
    for m in report.vuln_matches:
        ids = " ".join(m.cve + [_cwe_label(c) for c in m.cwe])
        badge = f"<span class='badge {_sev_class(m.severity)}'>{_esc(m.severity or 'info')}</span>"
        out.append(f"<div class='panel'>{badge}<b>{_esc(m.name)}</b> "
                   f"<span class='muted'>{_esc(ids)} — 매칭:{_esc(m.matched_on)}</span>"
                   + (f"<br><span class='muted'>{_esc(m.note)}</span>" if m.note else "")
                   + ("".join(f"<br>제안: <code>{_esc(s)}</code>" for s in m.suggest)) + "</div>")
    return "".join(out)


def _html_enriched(report) -> str:
    if not report.enriched:
        return "<p class='muted'>CVE 자동 수집 결과 없음(오프라인/비활성/미탐지)</p>"
    out = []
    for e in report.enriched:
        meta = " ".join(x for x in [e.severity, (f"CVSS {e.cvss}" if e.cvss else "")] if x)
        url = Enricher.cve_url(e.id)
        refs = "".join(f"<li>{_link(r)}</li>" for r in e.references[:3])
        pocs = "".join(f"<li>{_link(p)}</li>" for p in e.poc_repos[:3])
        out.append(
            f"<div class='panel'><b><a href='{_esc(url)}'>{_esc(e.id)}</a></b> "
            f"<span class='badge {_sev_class(e.severity)}'>{_esc(meta or 'n/a')}</span>"
            + (f"<br><span class='muted'>{_esc(e.description[:300])}</span>" if e.description else "")
            + (f"<br>CWE: {_esc(', '.join(_cwe_label(c) for c in e.cwe))}" if e.cwe else "")
            + (f"<br>참조:<ul>{refs}</ul>" if refs else "")
            + (f"공개 PoC:<ul>{pocs}</ul>" if pocs else "")
            + f"<span class='muted'>출처: {_esc(e.source)}</span></div>")
    return "".join(out)


def _html_flags(report) -> str:
    if report.flag_kind == "single":
        vals = [f.value for f in report.flags]
        return ("<p class='flag'>" + "  ".join(f"<code>{_esc(v)}</code>" for v in vals)
                + " ✅</p>") if vals else "<p class='muted'>플래그 미획득</p>"
    rows = []
    for kind, val in (("user", report.user_flag), ("root", report.root_flag)):
        if val:
            rows.append(f"<tr><td class='kcol'>{kind}.txt</td>"
                        f"<td class='flag'><code>{_esc(val)}</code> ✅</td></tr>")
        else:
            rows.append(f"<tr><td class='kcol'>{kind}.txt</td>"
                        f"<td class='muted'>미획득</td></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _html_list(items) -> str:
    if not items:
        return "<p class='muted'>없음</p>"
    return "<ul>" + "".join(f"<li><code>{_esc(s)}</code></li>" for s in items) + "</ul>"


def _html_revshell(report) -> str:
    shells = getattr(report, "revshells", None)
    if not shells:
        return "<p class='muted'>공격자 IP 미확보 — 생략</p>"
    head = (f"<p class='muted'>LHOST={_esc(report.revshell_lhost)} "
            f"LPORT={report.revshell_lport} · 생성만, 권한 확인 대상에서 직접 실행</p>")
    rows = "".join(
        f"<li><b>{_esc(s.name)}</b>: <code>{_esc(s.payload)}</code></li>" for s in shells)
    return head + "<ul>" + rows + "</ul>"


def _html_cloud(report) -> str:
    checks = getattr(report, "cloud_checks", None)
    if not checks:
        return "<p class='muted'>호스트명/도메인 미확보 — 생략</p>"
    cands = getattr(report, "cloud_candidates", [])
    head = (f"<p class='muted'>버킷 후보 {len(cands)}개 · 생성만, AWS 는 범위 밖·"
            "권한 확인 자산에서 직접 실행</p>")
    cand_html = ""
    if cands:
        cand_html = ("<p>버킷 후보: "
                     + ", ".join(f"<code>{_esc(c)}</code>" for c in cands) + "</p>")
    rows = "".join(
        f"<li><b>{_esc(c.name)}</b>: <code>{_esc(c.command)}</code></li>" for c in checks)
    return head + cand_html + "<ul>" + rows + "</ul>"


def _html_privesc(report) -> str:
    steps = getattr(report, "privesc_steps", None)
    if not steps:
        return "<p class='muted'>OS 미식별 — 생략</p>"
    rows = "".join(
        f"<li><b>{_esc(s.category)}</b>: <code>{_esc(s.command)}</code>"
        + (f" <span class='muted'>{_esc(s.note)}</span>" if s.note else "")
        + "</li>" for s in steps)
    out = "<p class='muted'>대상 셸에서 직접 실행 · 생성만</p><ul>" + rows + "</ul>"
    cands = getattr(report, "privesc_cve_candidates", [])
    if cands:
        out += ("<p><b>LPE CVE 후보:</b></p><ul>"
                + "".join(f"<li>{_esc(c)}</li>" for c in cands) + "</ul>")
    return out


def _html_crack(report) -> str:
    jobs = getattr(report, "crack_jobs", None)
    if not jobs:
        return "<p class='muted'>크래킹 대상 해시 미확보 — 생략</p>"
    blocks = ["<p class='muted'>생성만 · 사용자 환경에서 실행</p>"]
    for j in jobs:
        gnames = ", ".join(g.name for g in j.guesses) or "미상"
        rows = "".join(f"<li><b>{_esc(c.tool)}</b>: <code>{_esc(c.command)}</code></li>"
                       for c in j.commands)
        blocks.append(f"<p><code>{_esc(j.hash[:64])}</code> — {_esc(gnames)}</p>"
                      f"<ul>{rows}</ul>")
    return "".join(blocks)


def _html_knowledge(report) -> str:
    """지식 기반 패널: 완성형 시작 지식 · 검증된 성장 공유 · 이번 세션 자율 학습."""
    k = dict(getattr(report, "knowledge", {}) or {})
    acquired = list(getattr(report, "acquired_knowledge", []) or [])
    gaps = list(getattr(report, "knowledge_gaps", []) or [])
    tiles = []
    if k:
        cov = f"{k.get('catalog_covered', 0)}/{k.get('catalog_topics', 0)}"
        tiles += [("시작 지식(주제 커버)", cov, "ok"),
                  ("승격 발췌", k.get("promoted", 0), ""),
                  ("공유 최신본 반영", k.get("shared_overlays", 0), "")]
    tiles += [("이번 세션 자율 학습", len(acquired), "ok" if acquired else ""),
              ("미해석 공백", len(gaps), "warn" if gaps else "")]
    tile_html = "".join(
        f"<div class='tile {cls}'><div class='num'>{_esc(n)}</div><div class='lbl'>{_esc(lbl)}</div></div>"
        for lbl, n, cls in tiles)
    lines = []
    if k:
        latest = k.get("promoted_latest") or "-"
        sync = (k.get("last_sync") or "").replace("T", " ").replace("Z", " UTC") or "아직 없음"
        lines += [
            f"번들 시드 {_esc(k.get('seed_topics', 0))}개 — 누구나 clone 즉시 같은 지식으로 시작(오프라인 포함)",
            f"주간 자동 승격(품질 관문 + 전체 테스트 통과분만) — 최근 승격일 {_esc(latest)}",
            f"실행 시 하루 1회 공유 저장소와 검증 동기화 — 마지막 동기화 {_esc(sync)}",
        ]
    lines += [f"자율 학습: {_esc(a)}" for a in acquired[:5]]
    lines += [f"미해석 공백(수동 조사): {_esc(t)}" for t in gaps[:5]]
    body = ("<ul>" + "".join(f"<li>{x}</li>" for x in lines) + "</ul>") if lines else ""
    return f"<div class='panel'><b>지식 기반</b><div class='tiles'>{tile_html}</div>{body}</div>"


# 상태 배지: (색, 한국어 설명)
_STATUS = {"done": ("b-done", "완료"), "interrupted": ("b-high", "중단됨 — --resume 으로 이어서"),
           "escalate": ("b-crit", "사람 개입 필요"), "pending": ("b-info", "진행 전")}


def _html_result(report) -> str:
    """진행 결과 한 줄: 목표 달성·중단·escalate 여부와 요약 메시지."""
    badge = ("<span class='badge b-done'>목표 달성 — 남은 단계 조기 종료</span>"
             if getattr(report, "goal_reached", False) else "")
    msg = _esc(getattr(report, "message", "") or "")
    if not (badge or msg):
        return ""
    return f"<div class='panel'><b>진행 결과</b><br>{badge} <span class='muted'>{msg}</span></div>"


def _html_routing(report) -> str:
    """하이브리드 LLM 라우팅 패널 — 어느 백엔드가 실제로 응답했는지(하이브리드일 때만)."""
    r = dict(getattr(report, "llm_routing", {}) or {})
    if not r:
        return ""
    names = [("로컬 응답", "local", "ok"), ("강력 응답", "strong", "ok"), ("폴백", "fallback", ""),
             ("거절", "refusal", "warn"), ("빈 응답", "empty", ""), ("오류", "error", "warn"),
             ("미응답", "unserved", "warn")]
    tiles = "".join(
        f"<div class='tile {cls if r.get(k) else ''}'><div class='num'>{int(r.get(k, 0))}</div>"
        f"<div class='lbl'>{_esc(lbl)}</div></div>" for lbl, k, cls in names)
    off = r.get("disabled") or []
    note = (f"<p class='muted'>연속 오류로 세션 동안 건너뛴 백엔드: {_esc(', '.join(off))}</p>"
            if off else "")
    return f"<div class='panel'><b>LLM 라우팅 (하이브리드)</b><div class='tiles'>{tiles}</div>{note}</div>"


def _html_plan(report) -> str:
    """가설 보드 — 분석가가 세우고 갱신한 가설과 상태(결과 대조로 갱신, 〔추정〕)."""
    plan = getattr(report, "plan", None)
    if not plan:
        return ""
    focus = plan.focus()
    stuck = {h.id for h in plan.stuck()}
    cls = {"confirmed": "b-done", "rejected": "b-crit", "testing": "b-med", "pending": "b-info"}
    rows = "".join(
        f"<tr><td><b>{_esc(h.id)}</b>{' ← 지금' if focus is not None and h.id == focus.id else ''}</td>"
        f"<td><span class='badge {cls.get(h.status, 'b-info')}'>{_esc(h.label)}"
        f"{' · 막힘' if h.id in stuck else ''}</span></td>"
        f"<td>{_esc(h.priority)}</td><td>{_esc(h.text)}</td>"
        f"<td>{_esc(h.expected) or '-'}</td><td>{len(h.tried)}</td>"
        f"<td>{_esc('; '.join(h.evidence[-2:])) or '-'}</td></tr>"
        for h in plan.items)
    return ("<p class='muted'>분석가(강력 모델)가 세운 가설을 결과와 대조해 갱신합니다. 명령 생성은 "
            "'지금' 표시된 가설 하나에 집중하고, 같은 가설이 연속으로 어긋나면 재계획합니다. "
            "상태는 방향 잡기용〔추정〕 — 플래그·목표 판정은 실행 결과로만 합니다.</p>"
            "<table><tr><th>가설</th><th>상태</th><th>우선</th><th>내용</th><th>기대 신호</th>"
            f"<th>시도</th><th>최근 근거</th></tr>{rows}</table>")


def _html_analysis(report) -> str:
    text = getattr(report, "analysis", "") or ""
    if not text.strip():
        return "<p class='muted'>LLM 미사용 — 규칙 기반으로 진행</p>"
    return ("<p class='muted'>레드팀·개발자·인프라 운영자·방어 관점의 병렬 가설과 검증 계획. "
            "LLM 명령의 비고에 어떤 가설(H1…)을 검증했는지 남는다.</p>"
            f"<pre>{_esc(text)}</pre>")


def _html_overview(report) -> str:
    """심사위원·리뷰어용 한눈에 보기: 3관문 지표·플래그 출처·안전 경계·단계 진행."""
    gs = dict(getattr(report, "gate_stats", {}) or {})
    g = lambda k: int(gs.get(k, 0))  # noqa: E731
    tiles = [("제안", g("proposed"), ""), ("실행", g("executed"), "ok"),
             ("검토→수동 강등", g("denied_review"), "warn"),
             ("범위 밖 미실행", g("denied_scope"), "warn"),
             ("검증·범위 오류", g("rejected_validate") + g("rejected_scope"), "warn")]
    if g("tool_missing"):
        tiles.append(("도구 미설치", g("tool_missing"), ""))
    tile_html = "".join(
        f"<div class='tile {cls}'><div class='num'>{n}</div><div class='lbl'>{_esc(lbl)}</div></div>"
        for lbl, n, cls in tiles)

    provs = getattr(report, "flag_provenance", []) or []
    if provs:
        flag_html = "".join(
            f"<span class='badge {'b-done' if p.verdict == 'exploit-derived' else 'b-high'}'>"
            f"{_esc(p.kind)} · {_esc(p.label)}</span>" for p in provs)
    else:
        flag_html = "<span class='muted'>플래그 미획득</span>"

    target = getattr(report, "target", "")
    checks = [
        f"타겟 바인딩 <code>{_esc(target)}</code> — 자동 실행은 이 타겟·공격자·loopback 대상만"
        " (비정규 숫자 표기·IPv6 등 해석 불가 주소는 확인 대상)",
        "검토 대상(원격 코드 실행)·범위 밖 명령은 사람 승인 없이는 실행되지 않음(설계상 보장) — "
        f"이번 세션 수동 강등 {g('denied_review')}건 · 범위 밖 미실행 {g('denied_scope')}건",
        "LLM 제안·웹에서 가져온 내용도 신뢰하지 않는 입력으로 취급 — 모든 명령이 검증→범위→승인 3관문 통과",
        "HTB 라이트업은 출처 불문 자동 수집 차단 — 관측·권위 출처·사용자 본인 자료만 사용",
        "공유 지식은 데이터(노트)만 받고 품질 검증 통과분만 반영 — 코드는 받지 않음",
    ]
    from .orchestrator import PENTEST_PHASES  # 지연 import(순환 방지)
    labels = dict(PENTEST_PHASES)
    phases = dict(getattr(report, "phase_status", {}) or {})
    phase_html = ("<table>" + "".join(
        f"<tr><td class='kcol'>{_esc(labels.get(k, k))}</td><td>{_esc(v)}</td></tr>"
        for k, v in phases.items())
        + "</table>") if phases else "<p class='muted'>없음</p>"
    return (_html_result(report) +
            f"<div class='tiles'>{tile_html}</div>"
            "<p class='muted'>3관문 지표는 열거·LLM 명령 기준(정찰 포트스캔 제외).</p>"
            f"<div class='panel'><b>플래그 출처</b><br>{flag_html}</div>"
            + _html_knowledge(report) + _html_routing(report) +
            "<div class='panel'><b>안전 경계</b><ul class='checks'>"
            + "".join(f"<li>{c}</li>" for c in checks) + "</ul></div>"
            f"<div class='panel'><b>단계 진행</b>{phase_html}</div>")


def to_html(report, machine_name: str = "") -> str:
    prof = report.profile
    os_line = f"{prof.os_class.value} ({prof.tag}) · 확신도 {prof.confidence:.0%}" if prof else "-"
    name = machine_name or report.target
    status_badge, status_label = _STATUS.get(report.status, ("b-info", ""))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASSASSIN — {_esc(name)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>ASSASSIN · {_esc(name)}</h1>
<div class="sub">
  <span class="badge {status_badge}">{_esc(report.status)}{(" · " + _esc(status_label)) if status_label else ""}</span>
  <span class="badge b-info">{_esc(report.target)}</span>
  <span class="muted">OS: {_esc(os_line)} · 생성 {gen}</span>
</div>

<h2>한눈에 보기</h2>
{_html_overview(report)}

<h2>분석 (병렬 가설 · 계획)</h2>
{_html_plan(report)}
{_html_analysis(report)}

<h2>포트 &amp; 서비스</h2>
{_html_ports(report.host)}

<h2>취약점 (CVE / CWE)</h2>
{_html_vulns(report)}

<h2>CVE 레퍼런스 (NVD / PoC)</h2>
{_html_enriched(report)}

<h2>플래그</h2>
{_html_flags(report)}

<h2>리버스쉘 (자동 준비 · 생성만, 실행 안 함)</h2>
{_html_revshell(report)}

<h2>AWS/S3 열거 (자동 준비 · 생성만, 범위 밖·실행 안 함)</h2>
{_html_cloud(report)}

<h2>권한 상승 플레이북 (자동 준비 · 대상 셸에서 실행 · 생성만)</h2>
{_html_privesc(report)}

<h2>해시 크래킹 (자동 준비 · 사용자 환경에서 실행 · 생성만)</h2>
{_html_crack(report)}

<h2>수동 제안 (승인/입력 후 실행)</h2>
{_html_list(report.manual_suggestions)}

<div class="foot">자동 생성(ASSASSIN) · 관측·사용자 자료 기반 · 외부 라이트업 미참조 ·
권한이 확인된 대상 전용</div>
</div></body></html>
"""
