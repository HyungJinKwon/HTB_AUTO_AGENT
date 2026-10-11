"""플래그 출처 분류·확신도 평가 (S4-3 god-object 해체(2): 비실행 응집 클러스터 추출).

플래그를 '어떻게 알았나'(provenance)로 분류하고, 포착된 플래그를 '독립 재현' 관점에서
재채점(confidence)하는 로직을 Orchestrator 밖 자유 함수로 떼어낸다. 전부 **분석·판정 전용**
(실행·발사 없음). self 상태 의존을 명시 인자(workspace·kb)로 바꿔 단위 검증을 가능케 한다.

Orchestrator 의 `_classify_flag`/`_flag_in_external_notes`/`_assess_flags` 는 이 함수들로
위임하는 얇은 래퍼로 남는다(행위 보존).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import provenance as _prov

if TYPE_CHECKING:
    from .orchestrator import OrchestrationReport


def flag_in_external_notes(value: str, kb) -> bool:
    """플래그 값이 웹학습·ingest 등 '외부에서 가져온' 노트 본문에 그대로 있는가(looked-up 판정).
    사용자가 직접 올린 라이트업(ingest)이라도, 플래그가 거기 적혀 있었다면 공략이 아니라 '본 것'
    이므로 사람이 확인하도록 표시한다. 번들 시드(공략 흔적 없는 레퍼런스)는 제외."""
    if not value or kb is None:
        return False
    try:
        notes = kb.external_notes()
    except Exception:   # noqa: BLE001 — 분류 보조 실패가 본 작업을 막지 않음
        return False
    return any(value in n for n in notes)


def classify_flag(report: "OrchestrationReport", hit, cmd: str, phase: str,
                  workspace, kb):
    """출처 분류 + 작업공간 보정.
    - 에이전트가 쓴 스크립트 본문에 플래그 문자열이 그대로 있으면 '로컬 유래'(지어낸 값일 수 있음)
    - 첨부파일만 있는 문제(열린 포트 없음)에서 files/ 를 읽은 로컬 명령의 출력은 풀이 결과로 인정"""
    # 외부/학습 자료(웹학습·ingest 노트)에 플래그가 그대로 있으면 looked-up(라이트업·검색 의심)
    in_external = flag_in_external_notes(hit.value, kb)
    prov = _prov.classify(hit.kind, hit.value, cmd, phase, in_external=in_external)
    if prov.verdict in ("reasoning-only", "looked-up"):
        return prov
    ws = workspace
    if ws is None:
        return prov
    for rel in ws.written:
        try:
            with open(ws.resolve(rel), encoding="utf-8", errors="replace") as f:
                if hit.value in f.read():
                    prov.verdict = "local-derived"
                    prov.reason = f"에이전트가 작성한 {rel} 본문에 플래그 문자열 포함 — 지어낸 값일 수 있음"
                    return prov
        except OSError:
            continue
    offline = report.host is not None and not report.host.open_ports
    if offline and prov.verdict == "local-derived" and "files/" in cmd:
        prov.verdict = "exploit-derived"
        prov.reason = "첨부파일 분석 출력에서 추출(오프라인 문제)"
    return prov


def assess_flags(report: "OrchestrationReport") -> None:
    """포착된 플래그를 '독립 재현' 관점에서 재채점(verify.assess)해 report.flag_confidence 에
    싣는다. 공략 유래지만 단일 출처면, 다른 방법으로 재읽기하는 독립 명령을 수동 제안에 1회 남겨
    사람이 재확인하도록 한다(생성 전용 — 실행은 3관문). 신뢰 판정을 바꾸지 않는다."""
    from . import verify
    for f in report.flags:
        conf = verify.assess(f.kind, f.value, report.flag_provenance)
        report.flag_confidence[(f.kind, f.value)] = conf
        if conf.level == "single-source" and conf.sources:
            rereads = verify.reread_commands(conf.sources[0])
            if rereads:
                report.manual_suggestions.append(
                    f"# 🔎 재검증(단일 출처 플래그 {f.kind}) — 같은 값을 '다른 방법'으로 "
                    f"재읽기해 재현되면 신뢰도 상승(권한 확인 대상 전용):\n"
                    + "\n".join(f"#   - {c}" for c in rereads))
