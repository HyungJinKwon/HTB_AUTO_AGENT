"""자동 '준비' 생성기 (S4-3 — god-object 해체: 비실행 응집 클러스터 추출).

리버스쉘 페이로드·클라우드(S3) 열거·권한상승 플레이북·해시 크래킹 작업을 **생성만** 한다
(실행·발사 없음 — 안전 경계). 과거 Orchestrator 안에 흩어져 있던 `_prepare_*`·
`_privesc_analyze_stage` 를 self 상태 의존 없이 '명시 인자 → report 변이' 자유 함수로 떼어내,
오케스트레이터의 god-object 표면을 줄이고 각 준비 로직을 단위로 검증 가능하게 한다.

Orchestrator 의 동명 메서드는 이 함수들로 위임하는 얇은 래퍼로 남는다(행위 보존). `audit` 은
`event(...)` 만 호출하는 덕타이핑 객체(NullAudit 등). report 는 OrchestrationReport.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .crack import scan_hashes as crack_scan

if TYPE_CHECKING:
    from .orchestrator import OrchestrationReport
    from .target_profiler import ProfileResult


def prepare_revshells(report: "OrchestrationReport", attacker_ips: list[str],
                      revshell_port: int, audit) -> None:
    """공격자 IP(VPN tun0 등)가 확보되면 리버스쉘 페이로드를 자동 생성해 리포트에 담는다.
    생성 전용 — 실행하지 않는다(안전 경계). 공격자 IP 가 없으면 조용히 생략."""
    if not attacker_ips:
        return
    lhost = str(attacker_ips[0])
    lport = revshell_port
    try:
        from . import revshell
        report.revshells = revshell.generate(lhost, lport)
        report.revshell_lhost = lhost
        report.revshell_lport = lport
        audit.event("revshell_prepared", lhost=lhost, lport=lport,
                    count=len(report.revshells))
    except Exception as e:   # noqa: BLE001 — 생성 실패가 전체를 깨지 않도록
        audit.event("revshell_error", error=str(e))


def prepare_cloud(report: "OrchestrationReport", names: list[str], audit) -> None:
    """호스트명/도메인이 확보되면 AWS/S3 열거(버킷 후보+점검)를 자동 준비한다. 생성 전용 —
    AWS 엔드포인트는 타겟 범위 밖이라 실행하지 않는다. 이름(호스트명/도메인)이 없으면 생략."""
    try:
        from . import cloud
        prep = cloud.generate(names)
        if not prep.candidates:
            return
        report.cloud_candidates = prep.candidates
        report.cloud_checks = prep.checks
        audit.event("cloud_prepared", keyword=prep.keyword,
                    candidates=len(prep.candidates), checks=len(prep.checks))
    except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
        audit.event("cloud_error", error=str(e))


def prepare_privesc(report: "OrchestrationReport", prof: "ProfileResult | None",
                    attacker_ip: str, audit) -> None:
    """OS 식별 결과로 권한상승 플레이북을 자동 준비한다. 생성 전용 — 획득한 대상 셸에서
    사용자가 직접 실행한다(에이전트는 셸 없음). OS 미상이면 생략. linux 는 벡터 분석도 수행."""
    os_class = prof.os_class.value if prof else "unknown"
    if os_class not in ("linux", "windows", "windows_ad"):
        return
    # 탐지 CVE(출력 추출) + 버전매칭 CVE 를 합쳐 LPE 후보 승격에 반영
    cve_pool = list(report.detected_cve)
    for m in report.vuln_matches:
        cve_pool.extend(m.cve)
    try:
        from . import privesc
        plan = privesc.build(os_class, attacker_ip, cve_pool)
        report.privesc_steps = plan.steps
        report.privesc_cve_candidates = plan.cve_candidates
        audit.event("privesc_prepared", os=os_class, steps=len(plan.steps),
                    cve_candidates=len(plan.cve_candidates))
        # ③ 폐루프 '후보 선정': 획득한 셸에서 이미 실행된 privesc 열거 출력(findings)이 있으면
        # 파싱해 구체적 상승 벡터를 랭킹한다(생성 전용 — 제안만, 실행 아님).
        if os_class == "linux":
            privesc_analyze(report, audit)
    except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
        audit.event("privesc_error", error=str(e))


def privesc_analyze(report: "OrchestrationReport", audit) -> None:
    """③ 폐루프 후보 선정 — findings 에 privesc 열거 출력(sudo -l·SUID·getcap)이 있으면 파싱해
    구체적 상승 벡터를 랭킹하고 수동 제안으로 surface 한다. 생성 전용(실행 아님). 벡터의
    '실제 실행 → root 확인 → world 권한레벨 전이 → 재열거'(폐루프 발사)는 사용자 리포의 실행
    스테이지(target_shell) 몫 — 여기선 후보·계획만 만든다."""
    corpus = "\n".join(f.output for f in (report.enum_findings + report.llm_findings)
                       if f.output)
    if not corpus.strip():
        return
    from .privesc_analyze import analyze_enum, render_vectors
    vectors = analyze_enum(corpus)
    if not vectors:
        return
    report.privesc_vectors = vectors
    suggestion = render_vectors(vectors)
    if suggestion not in report.manual_suggestions:
        report.manual_suggestions.append(
            "# 권한상승 벡터(열거 출력 자동 분석 — 권한 확인 자산 전용):\n" + suggestion)
    audit.event("privesc_vectors", count=len(vectors),
                kinds=[v.kind for v in vectors[:5]])


def prepare_crack(report: "OrchestrationReport", found_hashes: list[str],
                  vault, audit) -> None:
    """enum/LLM 출력·크리덴셜 볼트에서 해시를 수집해 크래킹 명령을 자동 준비한다. 생성 전용 —
    크래킹은 사용자 환경에서 실행. 해시가 없으면 조용히 생략."""
    # 실행 원시출력에서 수집한 해시(요약 전 — _attempt 에서 스캔) + 요약출력 보강
    hashes: list[str] = list(found_hashes or [])
    for f in report.enum_findings + report.llm_findings:
        if f.output:
            hashes.extend(crack_scan(f.output))
    for p in report.host.ports if report.host else []:
        for sc in p.scripts.values():
            hashes.extend(crack_scan(sc))
    # 크리덴셜 볼트의 NT 해시(PtH)도 크래킹 후보
    if vault is not None:
        for c in vault.creds:
            nt = getattr(c, "nt_hash", None)
            if nt:
                # PtH NT 해시는 'LM:NT' 형식일 수 있어 NT 부분만 사용
                hashes.append(nt.split(":")[-1])
    if not hashes:
        return
    try:
        from . import crack
        report.crack_jobs = crack.prepare(hashes)
        if report.crack_jobs:
            audit.event("crack_prepared", jobs=len(report.crack_jobs))
    except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
        audit.event("crack_error", error=str(e))
