"""
Doctor — 환경 자가진단 (완전 초보자용)
=======================================

`assassin --doctor` 로 스캔 없이 '지금 쓸 준비가 됐는지'를 한눈에 점검한다.
각 항목을 ✔/▲/✘ 로 보여주고, 안 된 항목마다 '다음에 뭘 하면 되는지'를 바로
알려준다(복붙 가능한 명령). 네트워크·대상 없이 동작한다.

점검: 시스템(파이썬/OS/VPN) · 핵심 도구 · LLM 백엔드 · 종합 다음 단계.
"""
from __future__ import annotations

import platform
import sys

from . import __version__, ui
from .environment import _is_kali, detect_vpn_ips
from .tools import registry

# 초보자가 가장 먼저 필요한 '핵심' 도구(전체 63개 중). 나머지는 install_tools.sh.
ESSENTIAL_TOOLS = ["nmap", "curl", "ffuf", "gobuster", "netexec",
                   "smbclient", "sshpass", "hydra"]


_SETUP_HINT = "한 번에 연결: assassin --setup-llm"


def _check_llm(llm_test: bool = False, ollama_model: str = "",
               ollama_host: str = "") -> list[tuple[str, bool, str, str]]:
    """(이름, OK?, 상태, 설치힌트) 목록. import 실패도 안전 처리.
    llm_test=True 면 사용 가능한 백엔드에 짧은 요청 1회를 보내 실제 응답까지 확인한다."""
    import os

    from . import llm_setup
    rows: list[tuple[str, bool, str, str]] = []
    try:
        from .llm.claude_provider import ClaudeProvider
        prov_c = ClaudeProvider()
        ok, reason = prov_c.available()
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if ok and key:
            src = ("키 파일" if llm_setup.read_credentials()[0].get("ANTHROPIC_API_KEY") == key
                   else "환경변수")
            reason = f"키 {llm_setup.mask(key)} ({src})"
        if ok and llm_test:
            ok, msg = llm_setup.test_provider(prov_c)
            reason = (reason + " · " if ok else "") + ("호출 OK — " if ok else "호출 실패 — ") + msg
        rows.append(("Claude(API)", ok, reason,
                     f"{_SETUP_HINT}  (수동: pip install anthropic && export ANTHROPIC_API_KEY=sk-ant-...)"))
    except Exception as e:                       # noqa: BLE001 - 진단은 중단 금지
        rows.append(("Claude(API)", False, f"로드 실패: {llm_setup.scrub(str(e))}",
                     f"{_SETUP_HINT}  (수동: pip install anthropic)"))
    try:
        from .main import _ollama_provider
        prov = _ollama_provider(ollama_model, ollama_host)
        ok, reason = prov.available()
        if ok:
            from .llm.base import Tier
            reason = f"{prov.host} · 모델 {prov.model_for(Tier.STANDARD)}"
        if ok and llm_test:
            from .llm.base import Tier
            ok, msg = llm_setup.test_provider(prov, Tier.STANDARD)
            reason = (reason + " · " if ok else "") + ("호출 OK — " if ok else "호출 실패 — ") + msg
        rows.append(("Ollama(로컬)", ok, reason,
                     f"{_SETUP_HINT}  (수동: 'ollama serve' + 'ollama pull qwen2.5:7b', "
                     f"호스트 {prov.host})"))
    except Exception as e:                       # noqa: BLE001
        rows.append(("Ollama(로컬)", False, f"로드 실패: {llm_setup.scrub(str(e))}",
                     f"{_SETUP_HINT}  (수동: https://ollama.com 설치 후 'ollama pull qwen2.5:7b')"))
    return rows


def _capability_grade(strong_llm: bool, any_llm: bool, essentials_ok: bool,
                      sandbox_ok: bool) -> tuple[str, list[str]]:
    """환경 역량 등급과 '한 단계 올리는 법'을 반환(G2). 사용자·환경별 성능 편차를 가시화한다.
      full     = 강력 LLM(claude/hybrid) + 핵심 도구 + 실행 샌드박스(docker/vm)
      standard = (LLM 아무거나) 또는 핵심 도구 — 규칙+적응이 제대로 도는 상태
      baseline = LLM 없음 + 핵심 도구 미비 — 규칙 기반 최소 동작
    등급은 안전·정확성과 무관(모든 등급에서 3관문·범위 강제 동일). 성능/자율성의 폭을 나타낸다."""
    tips: list[str] = []
    if strong_llm and essentials_ok and sandbox_ok:
        return "full", ["최상위 — 완전자율(--autonomous --sandbox docker --llm hybrid) 권장"]
    if not strong_llm:
        tips.append("강력 LLM 연결(assassin --setup-llm → hybrid/claude): 분석·명령 품질↑")
    if not essentials_ok:
        tips.append("핵심 도구 설치(assassin --install-missing): 열거·공격 커버리지↑")
    if not sandbox_ok:
        tips.append("실행 샌드박스(docker 설치 + ./scripts/build_sandbox.sh): 스크립트·동적 실행 자동화")
    grade = "standard" if (any_llm or essentials_ok) else "baseline"
    return grade, tips


def run_doctor(llm_test: bool = False, ollama_model: str = "",
               ollama_host: str = "") -> tuple[str, bool]:
    """진단 텍스트와 '치명적 문제 없음' 여부를 반환."""
    blocking = False
    out: list[str] = [ui.banner("환경 자가진단 (완전 초보자용)")]

    # 1) 시스템
    sys_lines = []
    pyok = sys.version_info >= (3, 10)
    pv = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    sys_lines.append((ui.mark_ok if pyok else ui.mark_err)(f"Python {pv}")
                     + ("" if pyok else ui.dim("  → 3.10 이상 필요")))
    if not pyok:
        blocking = True
    is_linux = platform.system() == "Linux"
    if is_linux:
        sys_lines.append(ui.mark_ok("Linux" + (" (Kali)" if _is_kali()
                         else " — Kali 아님(일부 apt 패키지 상이 가능)")))
    else:
        sys_lines.append(ui.mark_warn(f"{platform.system()} — 실제 공격/VPN 은 Kali/Linux 권장"))
    vpn = detect_vpn_ips()
    if vpn:
        sys_lines.append(ui.mark_ok(f"VPN(tun/tap) IP: {', '.join(vpn)}"))
    else:
        sys_lines.append(ui.mark_warn("VPN(tun/tap) 미탐지")
                         + ui.dim("  → HTB는 'sudo openvpn 파일.ovpn' (CTF/로컬은 불필요)"))
    out.append(ui.panel("1. 시스템", sys_lines, style="navy"))

    # 2) 핵심 도구
    avail = registry.check_available()
    tool_lines = []
    missing_ess = []
    for k in ESSENTIAL_TOOLS:
        t = registry.TOOLS_BY_KEY.get(k)
        if t is None:
            continue
        path = avail.get(k)
        if path:
            tool_lines.append(ui.mark_ok(f"{k:10}") + ui.dim(path))
        else:
            missing_ess.append(k)
            tool_lines.append(ui.mark_err(f"{k:10}") + ui.dim("미설치 → " + t.install_hint()))
    total = len(registry.TOOLS)
    installed = sum(1 for v in avail.values() if v)
    tool_lines.append(ui.dim(f"전체 도구 {installed}/{total} 설치됨"))
    if missing_ess:
        tool_lines.append(ui.accent2("일괄 설치: ") + ui.bold("assassin --install-missing")
                          + ui.dim("  (또는 sudo ./scripts/install_tools.sh)"))
    out.append(ui.panel("2. 핵심 도구", tool_lines, style="navy"))

    # 3) LLM 백엔드(선택)
    llm_lines = []
    any_llm = False
    strong_llm = False   # claude/hybrid 등 비-ollama 백엔드 가용(역량 등급용)
    for name, ok, reason, hint in _check_llm(llm_test, ollama_model, ollama_host):
        short = reason if len(reason) <= 90 else reason[:87] + "..."
        if ok:
            any_llm = True
            if "ollama" not in name.lower():
                strong_llm = True
            llm_lines.append(ui.mark_ok(f"{name:14}") + ui.dim(short))
        else:
            llm_lines.append(ui.mark_warn(f"{name:14}") + ui.dim(short))
            llm_lines.append(ui.dim(f"   → {hint}"))
    if any_llm:
        llm_lines.append(ui.ok("LLM 사용 가능") + ui.dim("  (--llm hybrid/claude/ollama)"))
        if not llm_test:
            llm_lines.append(ui.dim("실제 호출까지 확인: assassin --llm-test"))
    else:
        llm_lines.append(ui.info("LLM 없이도 규칙기반으로 완전 동작")
                         + ui.dim("  (--llm none, 기본값)"))
        llm_lines.append(ui.accent2("LLM 연결(처음 한 번): ") + ui.bold("assassin --setup-llm"))
    out.append(ui.panel("3. LLM 두뇌 (선택)" + (" — 실제 호출 테스트" if llm_test else ""),
                        llm_lines, style="navy"))

    # 3.5) 실행 샌드박스(선택) — 완전자율에서 스크립트·동적 실행을 어디서 돌릴지
    import shutil as _sh
    sb_lines = []
    sb_lines.append(ui.info("none") + ui.dim("  기본 — 로컬에서 한 줄씩(파이프·스크립트 불가). 안전·간단"))
    if _sh.which("docker"):
        sb_lines.append(ui.mark_ok("docker") + ui.dim("  Kali 컨테이너+egress 방화벽 — 완전자율 권장. "
                                                       "이미지: ./scripts/build_sandbox.sh"))
    else:
        sb_lines.append(ui.mark_warn("docker") + ui.dim("  미설치 — 설치 후 ./scripts/build_sandbox.sh"))
    sb_lines.append((ui.mark_ok if _sh.which("ssh") else ui.mark_warn)("vm")
                    + ui.dim("  SSH 로 접속한 가상머신/공격호스트에서 실행 — "
                             "--sandbox vm --vm-ssh user@host (완전자율 자동은 --vm-confine)"))
    sb_lines.append(ui.dim("고르는 법: 평소엔 none, 완전자율(--autonomous)엔 docker, "
                           "전용 Kali VM 이 있으면 vm"))
    out.append(ui.panel("3.5 실행 샌드박스 (선택)", sb_lines, style="navy"))

    # 3.9) 역량 등급(G2) — 환경·사용자별 성능 편차를 한눈에 + 올리는 법
    sandbox_ok = bool(_sh.which("docker") or _sh.which("ssh"))
    grade, tips = _capability_grade(strong_llm, any_llm, not missing_ess, sandbox_ok)
    _GRADE_LABEL = {"full": ui.ok("full (최상위)"),
                    "standard": ui.info("standard (표준)"),
                    "baseline": ui.mark_warn("baseline (최소)")}
    grade_lines = [ui.kv("현재 등급", _GRADE_LABEL.get(grade, grade), 10),
                   ui.dim("  등급은 성능·자율성의 폭 — 안전·범위 강제는 모든 등급 동일")]
    for tip in tips:
        grade_lines.append(ui.mark_run("↑ ") + tip)
    out.append(ui.panel("3.9 역량 등급", grade_lines, style="navy"))

    # 4) 종합 · 다음 단계
    nxt = []
    if blocking:
        nxt.append(ui.mark_err("치명적: Python 3.10+ 로 업그레이드 후 다시 시도"))
    if missing_ess:
        nxt.append(ui.mark_run("도구 설치: ") + "assassin --install-missing")
    if not vpn:
        nxt.append(ui.mark_run("HTB면 VPN 연결: ") + "sudo openvpn <파일>.ovpn")
    nxt.append(ui.mark_run("첫 실행(HTB): ") + "assassin 10.129.x.x")
    nxt.append(ui.mark_run("첫 실행(CTF): ") + "assassin chall.site:1337 --platform ctf")
    nxt.append(ui.dim("자세한 운영/문제해결: docs/OPERATIONS.md"))
    out.append(ui.panel("4. 다음 단계", nxt,
                        style="accent" if not blocking else "warn"))

    from .knowledge import KB_VERSION
    out.append(ui.dim(f"ASSASSIN {__version__} · KB v{KB_VERSION} · "
                      "이 진단은 네트워크·대상 없이 동작합니다."))
    return "\n".join(out), not blocking
