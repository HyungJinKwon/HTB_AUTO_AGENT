"""
Results Verifier (출력 구동 교정) — 실행 '후' 출력을 읽고 명령을 고쳐 재시도
================================================================================

AutoPentester(2510.05605) Results Verifier 의 '출력구동' 축을 승인제 구조에 맞춰 **결정적
(규칙 기반)**으로 이식한다. `command_fixer.py` 가 실행 *전* 타겟 자리표시자·오입력 IP 만
복구한다면, 이 모듈은 실행 *후* 출력/오류를 보고 '거의 맞았는데 한 끗 빠진' 명령(필터된
호스트에 -Pn 누락, 자가서명 TLS 에 -k 누락, 리다이렉트에 -L 누락 등)을 교정한다.

안전·경계(이 구현의 원칙):
  · **고신뢰 소수 규칙만** — 애매하면 교정하지 않는다(과잉 재시도·예산 낭비 방지).
  · **생성 전용** — 교정본은 '문자열 제안'일 뿐, 오케스트레이터가 검증→범위→승인 3관문에
    다시 넣어 실행한다. 이 모듈은 명령을 실행하지 않는다(네트워크·상태 변경 없음).
  · **유한** — 원 명령당 교정은 호출부에서 1회로 제한, 교정본은 또 교정하지 않는다(재귀 방지).
  · 이미 해당 플래그가 있으면 교정하지 않는다(멱등).
"""
from __future__ import annotations

import re

from .util import binary_index, binary_of


def _insert_flag(cmd: str, flag: str) -> str:
    """실제 바이너리 바로 뒤에 플래그를 끼운다(선행 env-prefix·래퍼는 건너뜀).
    'nmap 10.0.0.1' → 'nmap -Pn 10.0.0.1', 'sudo nmap x' → 'sudo nmap -Pn x',
    'PROXY=1 nmap x' → 'PROXY=1 nmap -Pn x'."""
    toks = cmd.strip().split()
    if not toks:
        return cmd
    i = binary_index(toks)            # 바이너리 인덱스(env-prefix/래퍼 skip)
    if i >= len(toks):                # 바이너리 없음(전부 env-prefix 등) — 손대지 않음
        return cmd
    return " ".join(toks[: i + 1] + [flag] + toks[i + 1:])


def _has_token(cmd: str, *tokens: str) -> bool:
    """명령에 토큰(플래그)이 이미 있는지. 단일 대시 단축플래그는 결합형(-sSL 의 L)도 인정.
    단축 플래그는 **대소문자 구분**한다 — curl `-K`(설정파일) 가 `-k`(--insecure) 로 오인돼
    자가서명 TLS 교정을 삼키던 문제(감사 B-LOW4) 방지. nmap `-Pn`/`-pn` 은 호출부가 두 형태를
    모두 넘겨 커버한다."""
    padded = f" {cmd} "
    toks = cmd.split()
    for t in tokens:
        if f" {t} " in padded or f" {t}=" in padded:
            return True
        if re.fullmatch(r"-[A-Za-z]", t):   # 결합형 단축플래그: -L 이 -sSL 안에 있으면 True
            letter = t[1]
            for tk in toks:
                if re.fullmatch(r"-[A-Za-z]+", tk) and letter in tk[1:]:
                    return True
    return False


def corrective_command(cmd: str, out) -> tuple[str, str] | None:
    """실행 결과(out: RunOutput 유사 — .stdout/.stderr 보유)를 보고 교정본을 제안.
    반환 (교정된 명령, 사유) 또는 None(교정 없음). 결정적·보수적."""
    if not cmd:
        return None
    binary = binary_of(cmd, strip_path=True, skip_wrappers=True)
    text = ((getattr(out, "stdout", "") or "") + "\n"
            + (getattr(out, "stderr", "") or "")).lower()
    if not text.strip():
        return None

    # 1) nmap: 호스트가 ping 을 막아 '다운'으로 보이거나 전부 filtered → -Pn 추가(호스트는 이미 범위 내)
    if binary == "nmap" and not _has_token(cmd, "-Pn", "-pn"):
        if ("host seems down" in text or "0 hosts up" in text
                or "if it is really up, but blocking" in text
                or ("filtered" in text and "open" not in text and "nmap done" in text)):
            return _insert_flag(cmd, "-Pn"), "nmap: 호스트 다운/필터 응답 → -Pn(ping 생략)"

    # 2) curl: https 자가서명/인증서 검증 실패 → -k(검증 생략). HTB 자가서명에 흔함.
    if binary == "curl" and "https://" in cmd.lower() and not _has_token(cmd, "-k", "--insecure"):
        if ("ssl certificate problem" in text or "self signed certificate" in text
                or "unable to get local issuer" in text
                or "certificate verify failed" in text):
            return _insert_flag(cmd, "-k"), "curl: TLS 자가서명/검증실패 → -k"

    # 3) curl: 3xx 리다이렉트인데 따라가지 않음 → -L(따라가기)
    if binary == "curl" and not _has_token(cmd, "-L", "--location"):
        if re.search(r"\b30[12378]\b", text) and ("location:" in text or "moved" in text
                                                  or "redirect" in text):
            return _insert_flag(cmd, "-L"), "curl: 리다이렉트(3xx) → -L(따라가기)"

    return None
