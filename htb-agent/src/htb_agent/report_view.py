"""
Report View — 오케스트레이션 결과의 터미널 렌더링
=================================================

OrchestrationReport 의 '출력(요약·한눈에보기·다음행동)'을 orchestrator 에서 떼어낸 모듈.
상태·판정 로직과 렌더링을 분리한다. OrchestrationReport 의 summary()/glance() 는 여기로 위임하며
공개 API 는 그대로다(기존 호출부 무변경).
"""
from __future__ import annotations


def next_actions(report) -> list[str]:
    """현재 상태에서 초보자가 바로 할 수 있는 다음 행동(구체 명령). 새 공격을 만들지 않고
    이미 나온 상태·수동 제안을 '무엇을 입력하면 되는지'로 바꿔 줄 뿐이다."""
    out: list[str] = []
    rec = report.recon
    if report.status == "escalate" and rec is not None:
        if not any(a.ran for a in rec.attempts):
            out.append("스캔 도구가 실행되지 못했습니다 → assassin --doctor 로 점검"
                       " (nmap 없으면: sudo apt install -y nmap)")
        else:
            out.append("대상이 응답하지 않습니다 → HTB 머신이 켜져 있는지(Spawn)·VPN 연결"
                       "(sudo openvpn <파일>.ovpn)을 확인한 뒤 다시 실행")
    if report.goal_reached:
        out.append("목표 달성 — 정리: 같은 명령에 --writeup --html 을 붙여 라이트업·대시보드 생성")
    over = sum(1 for m in report.manual_suggestions if "상한 초과" in m)
    if over:
        out.append(f"못 돌린 명령 {over}개 → 같은 명령 + --resume (이미 한 명령은 건너뜀)")
    if any(p in m for m in report.manual_suggestions for p in ("{user}", "{pass}", "{domain}")):
        out.append("자격증명이 필요한 명령이 있습니다 → 찾은 계정으로 --cred 사용자:비밀번호")
    if report.gate_stats.get("tool_missing", 0):
        out.append("설치되지 않은 도구가 있습니다 → sudo ./scripts/install_tools.sh")
    if report.status == "done" and not report.goal_reached and not out:
        out.append("위 '다음 선택지(NEXT OPTIONS)'에서 골라 승인 · 배우며 보려면 --manual")
    return out


# 익스플로잇 후보 묶음 제목(전용 — 맨 위에, 전부 표시). 자율 풀이의 핵심 결정이라 숨기지 않는다.
_EXPLOIT_TITLE = "🎯 익스플로잇 후보 — PoC 고르기"

# 수동 제안 분류: (제목, 초보자가 바로 하는 법, 판별 함수) — 위에서부터 먼저 맞는 것
_MANUAL_KINDS = [
(_EXPLOIT_TITLE, "대상 버전에 맞는 PoC 를 골라 --exploit-exec --poc \"<PoC>\" 로 실행하면 침입→자격→플래그가 이어집니다",
 lambda s: ("익스 후보" in s) or ("PoC 후보" in s)),
("자격증명이 필요한 명령", "--cred 사용자:비밀번호 를 붙여 다시 실행하면 자동으로 채워 실행합니다",
 lambda s: any(p in s for p in ("{user}", "{pass}", "{domain}", "{hash}"))),
("실행 위험 — 내용 확인 필요", "각 줄의 '대안'대로 먼저 내용을 확인한 뒤 직접 실행하세요",
 lambda s: "실행위험" in s),
("상한 초과로 미실행", "--max-enum 을 늘리거나 --resume 으로 이어서 실행하세요",
 lambda s: "상한 초과" in s),
("무거운 점검(직접 실행 권장)", "시간이 오래 걸려 자동 실행하지 않았습니다 — 필요할 때 복사해 실행",
 lambda s: "(수동)" in s),
]


_MANUAL_SHOW = 6   # 수동 제안 묶음마다 화면에 보여 줄 개수(나머지는 리포트에)


def render_glance(report) -> str:
    """맨 끝 '한눈에 보기' — 결과·찾은 것·실행 현황·다음에 할 일(최대 3개)을 한 박스로.
    긴 출력을 다 읽지 않아도 지금 상태와 다음 행동을 알 수 있게 한다(초보자용)."""
    from . import ui
    status = {"done": ui.ok("완료"), "interrupted": ui.warn("중단됨 — --resume 으로 이어서"),
              "escalate": ui.warn("사람 확인 필요"), "pending": ui.dim("진행 전")}.get(
        report.status, report.status)
    if report.flag_kind == "single":
        flag = ui.flag(report.flags[0].value) if report.flags else ui.dim("미획득")
    else:
        flag = (f"user {ui.ok('✔') if report.user_flag else ui.dim('✗')} · "
                f"root {ui.ok('✔') if report.root_flag else ui.dim('✗')}")
    ports = [f"{p.port}/{p.service or '?'}" for p in (report.host.ports if report.host else [])
             if p.state == "open"]
    w = report.world
    found = (f"자격증명 {len(w.creds) if w else 0} · 수집물 {len(w.loot) if w else 0} · "
             f"취약점 {len(report.vuln_matches) + len(report.detected_cve)}")
    gs = report.gate_stats
    runs = (f"실행 {gs.get('executed', 0)} · 도구 없음 {gs.get('tool_missing', 0)} · "
            f"미승인 {gs.get('denied_review', 0) + gs.get('denied_scope', 0)} · "
            f"못 돌림(상한) {sum(1 for m in report.manual_suggestions if '상한 초과' in m)}")
    rows = [ui.kv("결과", status + "   " + ui.dim("플래그 ") + flag, 8),
            ui.kv("서비스", ", ".join(ports) if ports else ui.dim("열린 포트 없음"), 8),
            ui.kv("찾은 것", found, 8),
            ui.kv("실행", runs, 8)]
    todo = next_actions(report)
    if todo:
        rows.append("")
        rows.append(ui.accent2("다음에 할 일"))
        rows += [f"  {i}. {t}" for i, t in enumerate(todo[:3], 1)]
    return ui.panel("한눈에 보기", rows, style="accent" if report.status == "done" else "warn")


def render_summary(report) -> str:
    from . import ui
    st = ui.ok if report.status == "done" else ui.accent2
    head = (ui.accent("ASSASSIN") + ui.dim(" · 오케스트레이션 ")
            + ui.bold(report.target) + "  " + st(f"[{report.status}]")
            + (("  " + ui.dim(report.message)) if report.message else ""))
    lines = [head, ui.rule("", 60, "navy")]
    if report.recon:
        lines.append(ui.heading("RECON", "📡"))
        lines.append(report.recon.summary())
    if report.profile:
        lines.append("\n" + ui.heading("PROFILE", "🧭"))
        lines.append(report.profile.summary())
    if report.world is not None:
        lines.append("\n" + ui.heading("STATE  (월드 모델 — 구조화 상태)", "🗺️"))
        lines.append(report.world.summary())
    if report.plan:
        lines.append("\n" + ui.heading(
            "PLAN  (가설 보드 — 분석가가 계획·갱신, 명령은 '지금 할 일'에 집중)", "🎯"))
        focus = report.plan.focus()
        for ln in report.plan.board_lines():
            is_focus = focus is not None and ln.split(" ", 2)[1] == focus.id
            lines.append("  " + (ui.accent2(ln + "  ← 지금") if is_focus else ln))
        lines.append("  " + ui.dim("상태는 방향 잡기용〔추정〕 — 플래그·목표 판정은 실행 결과로만 합니다."))
    if report.analysis:
        lines.append("\n" + ui.heading("ANALYSIS  (LLM 분석 — 병렬 가설·계획·경로)", "🧠"))
        for ln in report.analysis.splitlines():
            if ln.strip():
                lines.append("  " + ui.dim(ln.strip()))
    if report.acquired_knowledge or report.knowledge_gaps:
        lines.append("\n" + ui.heading(
            "LEARN  (자율 지식 획득 — 권위 출처만, P1 유지)", "🎓"))
        for a in report.acquired_knowledge:
            lines.append("  " + ui.ok("학습") + " " + a)
        for g in report.knowledge_gaps:
            lines.append("  " + ui.dim("미해석 공백(수동 조사): ") + g)
    # 모의해킹 단계 순서대로 그룹화 출력
    from .orchestrator import PENTEST_PHASES  # 지연 임포트(순환 회피)
    all_findings = report.enum_findings + report.llm_findings
    for key, label in PENTEST_PHASES:
        group = [f for f in all_findings if f.phase == key]
        st_label = report.phase_status.get(key, "")
        if group or st_label:
            suffix = ("  " + ui.dim(f"[{st_label}]")) if st_label else ""
            lines.append("\n" + ui.rule(f"단계: {label}{suffix}", 60))
        for f in group:
            mark = ui.mark_run() if f.ran else ui.dim("·")
            note = ui.dim(f"  — {f.note}") if f.note else ""
            lines.append(f"  {mark} {f.command}{note}")
            if f.output:
                lines.append("      " + ui.dim(f.output))
    if report.blockers:
        from . import diagnostics as _diag
        lines.append("\n" + ui.heading(
            "BLOCKERS  (막힌 지점 — 사람 확인용. 자동 재공격 아님)", "🧯"))
        diags = [d for _, d in report.blockers]
        tgt = [(c, d) for c, d in report.blockers if d.is_target]
        env = [(c, d) for c, d in report.blockers if not d.is_target]
        if tgt:
            lines.append("  " + ui.accent2("대상 응답(경로 판단에 유효):"))
            for cmd, d in tgt[:8]:
                lines.append(f"    · {d.label}  — {ui.dim(cmd[:60])}")
                if d.hint:
                    lines.append("      " + ui.dim("↳ " + d.hint))
        if env:
            lines.append("  " + ui.accent2("환경/도구/네트워크(경로 실패 아님):"))
            for cmd, d in env[:8]:
                lines.append(f"    · {d.label}  — {ui.dim(cmd[:60])}")
                if d.hint:
                    lines.append("      " + ui.dim("↳ " + d.hint))
        # 오판 방지: '대상이 거듭 거부'한 범주만 경로 재검토 후보로 '표시'(결정은 사람)
        signals = _diag.abandonment_signals(diags)
        repeated = {c: n for c, n in signals.items() if n >= 2}
        if repeated:
            lines.append("  " + ui.warn("경로 재검토 후보(대상이 2회+ 거부): ")
                         + ", ".join(f"{c}×{n}" for c, n in repeated.items())
                         + ui.dim("  — 환경 문제는 제외됨. 포기 여부는 사람이 판단."))
    from . import repetition as _rep
    _rr = _rep.analyze(report.enum_findings + report.llm_findings, report.blockers)
    if _rr.has_findings:
        lines.append("\n" + ui.heading(
            "REPETITION  (반복·정체 감지 — 사람 확인용. 자동 재계획 아님)", "🔁"))
        for sig, n in _rr.repeated_cmds[:6]:
            lines.append("  " + ui.warn(f"반복 명령 ×{n}: ") + ui.dim(sig))
        for cat, n in _rr.repeated_failures[:6]:
            lines.append("  " + ui.warn(f"같은 실패 ×{n}: ") + ui.dim(cat))
        if _rr.stalled:
            lines.append("  " + ui.warn("정체: ")
                         + ui.dim("실행은 여러 번이나 유의미한 출력이 희박 — 다른 각도를 사람이 검토"))
    if report.flag_provenance:
        lines.append("\n" + ui.heading(
            "PROVENANCE  (플래그 출처 검증 — 실행 트레이스 기반)", "🔎"))
        for p in report.flag_provenance:
            pmark = ui.ok if p.verdict == "exploit-derived" else ui.warn
            lines.append("  " + pmark(f"[{p.label}] ") + f"{p.kind} flag")
            lines.append("      " + ui.dim(f"↳ {p.reason} · {p.command[:60]}"))
        susp = [p for p in report.flag_provenance if p.verdict != "exploit-derived"]
        if susp:
            lines.append("  " + ui.warn(
                f"※ {len(susp)}건은 공략 유래가 아닐 수 있음 — 사람이 실제 공략 경로 확인"))
        # 적대적 재검증(skeptic) 확신도 — 독립 재현 여부(재현됨/단일 출처/미신뢰/미확정)
        conf = getattr(report, "flag_confidence", None) or {}
        if conf:
            lines.append("  " + ui.dim("재검증(skeptic) — 독립 재현 기준 확신도:"))
            for (kind, _val), c in conf.items():
                cmark = ui.ok if c.level == "reproduced" else ui.warn
                lines.append("    " + cmark(f"[{c.label}] ") + f"{kind} flag")
        # [A6] LLM-심판(조언) — 규칙 판정을 덮지 않는 보조 의견(opt-in --judge 일 때만 존재)
        jv = getattr(report, "judge_verdict", None)
        if jv is not None:
            jmark = ui.ok if getattr(jv, "passed", False) else ui.warn
            lines.append("  " + jmark(jv.label()))
    from . import recommend as _recommend
    _recs = _recommend.propose(report, repetition=_rr)   # 반복 분석 1회만
    if _recs.has_items:
        lines.append("\n" + ui.heading(
            "NEXT OPTIONS  (다음 선택지 — 사람이 골라 승인. 자동 실행 아님)", "🧭"))
        for i, r in enumerate(_recs.items, 1):
            lines.append(f"  {ui.accent2(str(i) + '.')} {r.title}")
            lines.append("      " + ui.dim("근거: " + r.rationale))
            if r.ref:
                lines.append("      " + ui.dim("참고: " + r.ref[:72]))
        lines.append("  " + ui.dim("→ 번호를 골라 해당 명령/각도를 승인하면 3관문을 거쳐 실행됩니다."))
    if report.detected_cve or report.detected_cwe or report.vuln_matches or report.discovered_cve:
        lines.append("\n" + ui.heading(
            "VULN  (탐지된 취약점 — 수동 검증/익스플로잇 필요)", "🛑"))
        if report.detected_cve:
            lines.append(ui.kv("탐지 CVE", ui.warn(", ".join(report.detected_cve)), 9))
        if report.discovered_cve:
            # 제품→CVE 역질의(NVD)로 자동 발견한 것 — KB 룰 없이도 신종 취약점을 수면 위로.
            lines.append(ui.kv("🔎 자동발견 CVE",
                               ui.warn(", ".join(report.discovered_cve)) + ui.dim(" (제품·버전 기반 NVD 역질의 — 버전대조 확인)"), 9))
        if report.detected_cwe:
            lines.append(ui.kv("탐지 CWE", ui.warn(", ".join(report.detected_cwe)), 9))
        for m in report.vuln_matches:
            sev = f"[{m.severity}] " if m.severity else ""
            ids = " ".join(m.cve + m.cwe)
            lines.append("  " + ui.mark_warn(
                ui.warn(sev) + m.name + ui.dim(f" ({ids}) — 매칭:{m.matched_on}")))
            if m.note:
                lines.append(ui.dim(f"       비고: {m.note}"))
            for s in m.suggest:
                lines.append("       " + ui.accent2("제안: ") + s)
    if report.enriched:
        lines.append("\n" + ui.heading("CVE 레퍼런스 (자동 수집 — NVD/GitHub)", "📚"))
        for e in report.enriched:
            sev = f"[{e.severity} {e.cvss}] " if e.severity else ""
            badge = ui.accent2("🔎 ") if e.id in report.discovered_cve else ""
            lines.append("  " + badge + ui.warn(sev) + ui.bold(e.id)
                         + (ui.dim("  " + ", ".join(e.cwe)) if e.cwe else ""))
            if e.description:
                lines.append(ui.dim("     " + e.description[:160]))
            for r in e.references[:3]:
                lines.append("     " + ui.accent2("ref: ") + ui.dim(r))
            for p in e.poc_repos[:3]:
                lines.append("     " + ui.accent2("PoC: ") + ui.dim(p))
    if report.flags:
        lines.append("\n" + ui.heading("🚩 플래그 (FLAG)"))
        if report.flag_kind == "single":
            for fh in report.flags:
                lines.append("  " + ui.flag(fh.value)
                             + ui.dim(f"  ← {fh.source}"))
        else:
            uf = ui.flag(report.user_flag) if report.user_flag else ui.dim("미획득")
            rf = ui.flag(report.root_flag) if report.root_flag else ui.dim("미획득")
            lines.append("  " + ui.dim("user.txt:") + " " + uf)
            lines.append("  " + ui.dim("root.txt:") + " " + rf)
            for fh in report.flags:
                if fh.kind == "unknown":
                    lines.append(ui.dim(f"  (미분류) {fh.value} ← {fh.source}"))
    if report.revshells:
        from .revshell import listener_hints
        lines.append("\n" + ui.heading(
            "리버스쉘 (자동 준비 — 초기 침투용 · 생성만, 에이전트는 실행 안 함)", "🐚"))
        lines.append(ui.dim(
            f"  LHOST={report.revshell_lhost}  LPORT={report.revshell_lport}"
            "  ·  권한 확인 대상에서 사용자가 직접 실행"))
        lines.append("  " + ui.accent2("리스너: ") + listener_hints(report.revshell_lport)[0])
        # 화면 잡음 축소(초보자): 대표 3개만 보여 주고 전체는 --json/--html 로
        _show = report.revshells[:3]
        for s in _show:
            lines.append("  " + ui.accent2(f"[{s.name}]"))
            lines.append("    " + s.payload)
        if len(report.revshells) > len(_show):
            lines.append(ui.dim(f"  … 외 {len(report.revshells) - len(_show)}종(bash/nc/python/php/"
                                "powershell/socat 등) — 전체는 --json/--html"))
    if report.cloud_checks:
        lines.append("\n" + ui.heading(
            "AWS/S3 열거 (자동 준비 — 생성만, AWS 는 범위 밖·실행 안 함)", "☁️"))
        if report.cloud_candidates:
            lines.append(ui.dim(
                f"  버킷 후보({len(report.cloud_candidates)}): "
                + ", ".join(report.cloud_candidates[:12])
                + (" …" if len(report.cloud_candidates) > 12 else "")))
        for c in report.cloud_checks:
            lines.append("  " + ui.accent2(f"[{c.name}] ") + c.command)
    if report.privesc_steps:
        lines.append("\n" + ui.heading(
            "권한 상승 플레이북 (자동 준비 — 대상 셸에서 실행 · 생성만)", "⬆️"))
        for s in report.privesc_steps:
            lines.append("  " + ui.accent2(f"[{s.category}] ") + s.command)
            if s.note:
                lines.append(ui.dim("      " + s.note))
        for c in report.privesc_cve_candidates:
            lines.append("  " + ui.mark_warn(ui.warn("LPE 후보: ") + c))
    if report.crack_jobs:
        lines.append("\n" + ui.heading(
            "해시 크래킹 (자동 준비 — 생성만, 사용자 환경에서 실행)", "🔑"))
        for j in report.crack_jobs:
            gnames = ", ".join(g.name for g in j.guesses) or "미상"
            lines.append("  " + ui.accent2("해시: ") + ui.dim(j.hash[:64]
                         + ("…" if len(j.hash) > 64 else "")))
            lines.append("    " + ui.dim(f"식별: {gnames}"))
            for c in j.commands:
                lines.append("    " + ui.accent2(f"[{c.tool}] ") + c.command)
    if getattr(report, "lateral_candidates", None):
        lines.append("\n" + ui.heading(
            "측면 이동 후보 (수확 크리덴셜/해시 재사용·PtH(Pass-the-Hash, 해시 그대로 재사용) "
            "— 생성만, 사용자 실행)", "↔"))
        _lat = report.lateral_candidates[:8]
        for c in _lat:
            lines.append("  " + ui.accent2(f"[{c.technique}/{c.service}] ") + c.command)
        if len(report.lateral_candidates) > len(_lat):
            lines.append(ui.dim(f"  … 외 {len(report.lateral_candidates) - len(_lat)}개"))
    if report.manual_suggestions:
        lines.append("\n" + ui.heading("수동 제안 — 종류별 바로 적용하는 법", "✋"))
        for title, how, items in _group_manual(report.manual_suggestions):
            lines.append("  " + ui.bold(f"{title} ({len(items)})") + "  " + ui.info("→ " + how))
            # 익스플로잇 후보는 '고를 대상'이므로 자르지 않고 전부 보여 준다(핵심 결정).
            if title == _EXPLOIT_TITLE:
                for s in items:
                    lines.append(ui.bullet(s, "·", "accent2"))
                continue
            # 초보자 화면: 옵션만 덧붙인 변형·같은 꼬리표는 숨기고 앞의 몇 개만(전체는 리포트에)
            shown = _compact_manual(items)
            for s in shown[:_MANUAL_SHOW]:
                lines.append(ui.bullet(s, "·", "dim"))
            rest = len(items) - min(len(shown), _MANUAL_SHOW)
            if rest > 0:
                lines.append("    " + ui.dim(f"… 외 {rest}개 (옵션 변형 포함) — 전체 목록: --html / --json 리포트"))
    solved = render_solved(report)
    if solved:
        lines.append("\n" + solved)
    lines.append("\n" + report.glance())
    return "\n".join(lines)


def render_solved(report) -> str | None:
    """'다 풀었다(SOLVED)' 결과 패널 — 목표 달성 시 저장된 플래그 값을 크게 보여 준다.
      · single(Jeopardy): 플래그 1개 획득 시
      · boot2root      : user.txt + root.txt 둘 다 획득 시
    미달성이면 None(패널 미표시). 값은 report.flags(저장 상태에서 복원됨)에서 읽는다."""
    from . import ui
    if report.flag_kind == "single":
        if not report.flags:
            return None
        rows = [ui.kv("flag", ui.flag(report.flags[0].value), 9)]
    else:
        uf, rf = report.user_flag, report.root_flag
        if not (uf and rf):
            return None
        rows = [ui.kv("user.txt", ui.flag(uf), 9),
                ui.kv("root.txt", ui.flag(rf), 9)]
    # 출처(정직성) — 전부 공략 유래면 '검증', 아니면 사람 확인 표식을 덧붙인다.
    provs = {p.verdict for p in report.flag_provenance}
    if provs and provs <= {"exploit-derived"}:
        rows.append(ui.dim("출처: 공략 유래(검증) — 대상 상호작용 출력에서 추출"))
    elif provs:
        rows.append(ui.mark_warn("출처: 일부 '사람 확인' 필요 — 🔎 PROVENANCE 참고"))
    return ui.panel("🏁 다 풀었다 (SOLVED)", rows, style="accent")


def _compact_manual(items: list[str]) -> list[str]:
    """화면용 정리: 같은 묶음 제목이 이미 말해 주는 꼬리표('# (상한 초과 — 수동)')를 떼고,
    앞 명령에 옵션만 덧붙인 변형(예: '... -L', '... -t 50')은 숨긴다."""
    out: list[str] = []
    for s in items:
        core = s.replace("   # (상한 초과 — 수동)", "").rstrip()
        if any(core.startswith(prev.split("   #")[0] + " ") for prev in out):
            continue
        out.append(core)
    return out


def _group_manual(items: list[str]) -> list[tuple[str, str, list[str]]]:
    groups: dict[str, list[str]] = {}
    hows: dict[str, str] = {}
    for s in items:
        for title, how, match in _MANUAL_KINDS:
            if match(s):
                break
        else:
            title, how = "기타 안내", "단계·플랫폼별 참고 명령입니다 — 필요한 것을 골라 실행하세요"
        groups.setdefault(title, []).append(s)
        hows[title] = how
    order = [k for k, _, _ in _MANUAL_KINDS] + ["기타 안내"]
    return [(t, hows[t], groups[t]) for t in order if t in groups]
