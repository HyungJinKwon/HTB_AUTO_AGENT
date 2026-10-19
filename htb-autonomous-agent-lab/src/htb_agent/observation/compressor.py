"""
Observation Compressor — 구조화 결과를 LLM 용으로 압축
=======================================================

파싱된 구조(NmapHost/HttpResult)를 LLM 컨텍스트에 넣기 좋은 **최소 요약**으로
압축한다. 원문 전체(수백~수천 줄)를 넣지 않아 토큰을 크게 절감한다(비용·속도).
또한 OS 판정을 바로 붙여 "지금 무엇을 아는가"를 한눈에 보이게 한다.
"""

from __future__ import annotations

from .parsers import NmapHost, NmapResult, HttpResult
from ..target_profiler import classify, ProfileResult


def summarize_nmap_host(host: NmapHost) -> dict:
    """한 호스트의 핵심만 추린 dict."""
    return {
        "host": host.address,
        "state": host.state,
        "open_ports": [str(p) for p in host.ports if p.state == "open"],
        "scripts": {k: (v[:200] + "…" if len(v) > 200 else v)
                    for k, v in host.hostscripts.items()},
    }


def profile_from_nmap(host: NmapHost) -> ProfileResult:
    """파싱된 호스트에서 바로 OS/역할 판정."""
    pi = host.to_profile_inputs()
    return classify(pi["open_ports"], banners=pi["banners"],
                    script_output=pi["script_output"])


def render_observation(host: NmapHost, http: HttpResult | None = None) -> str:
    """LLM/사용자에게 보여줄 압축 관측 요약 텍스트."""
    prof = profile_from_nmap(host)
    lines = [
        f"# 관측 요약 — {host.address or '(미상)'} ({host.state})",
        f"열린 포트({len(host.open_ports)}): "
        + (", ".join(str(p) for p in host.ports if p.state == "open") or "없음"),
    ]
    if host.hostscripts:
        lines.append("host 스크립트: " + ", ".join(host.hostscripts.keys()))
    lines.append("")
    lines.append(prof.summary())
    if http is not None and http.status is not None:
        lines.append("")
        lines.append("HTTP: " + http.summary())
    return "\n".join(lines)


def recommend_followup(result: NmapResult) -> list[str]:
    """
    파싱 결과로부터 '경우의 수'(다음 시도) 후보를 제시. 실행은 하지 않는다.
    무한루프 방지를 위해 상위 레이어가 유한 횟수로만 소비한다.
    """
    suggestions: list[str] = []
    if result.seems_down or not result.any_up:
        suggestions.append("-Pn (호스트 디스커버리 생략 — 핑 차단 대비)")
        suggestions.append("-sT (TCP connect 스캔 — 권한/필터 이슈 대비)")
    host = result.first_host()
    if host and host.state == "up" and not host.open_ports:
        suggestions.append("-p- (전체 포트 — 상위 1000 밖 서비스 대비)")
        suggestions.append("-sU --top-ports 20 (상위 UDP)")
    return suggestions
