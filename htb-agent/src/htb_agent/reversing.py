"""
export-first 리버싱 — 바이너리를 '정적'으로 일괄 추출→로컬 분석 (redcat2 doctrine/60 이식)
================================================================================================

rev/pwn/forensic 첨부 바이너리를 받으면, 먼저 **정적 분석**(바이너리를 실행하지 않는 도구)으로
한꺼번에 추출해 사람이 로컬에서 훑어보게 한다. redcat2 의 'export-first → local grep → surgical'
워크플로를 이 도구의 생성 전용·승인제 구조에 맞춰 결정적으로 이식.

안전·경계:
  · **정적 분석만** — file/strings/nm/objdump/checksec/radare2(-A 정적). 바이너리를 **실행하지
    않는다**(gdb 실행·`./바이너리`·ltrace/strace 같은 동적 실행은 제외 — 신뢰 불가 파일 실행 금지).
  · **생성 전용** — 명령 '문자열'만 만든다. 실행은 3관문(검증→범위→승인)을 거친다.
  · 경로는 shlex 로 안전 인용(공백·특수문자 주입 차단).
"""
from __future__ import annotations

import shlex


def export_first_commands(path: str) -> list[str]:
    """바이너리 경로에 대한 정적 분석 명령 목록(결정적 순서). 가벼운 식별 → 무거운 디스어셈블 순."""
    if not path or not str(path).strip():
        return []
    p = shlex.quote(str(path))
    return [
        f"file {p}",                                    # 포맷·아키텍처·링크 식별
        f"strings -n 8 {p}",                            # 인쇄가능 문자열(플래그·경로·힌트)
        f"strings -e l -n 6 {p}",                       # 와이드(UTF-16LE) 문자열
        f"nm -C {p}",                                   # 심볼(디맹글)
        f"checksec --file={p}",                         # 보호기법(NX/PIE/Canary/RELRO)
        f"objdump -d -M intel {p}",                     # 정적 디스어셈블(Intel 문법)
        f"r2 -A -q -c 'iI ; afl ; izz' {p}",            # radare2 정적 분석(헤더·함수·문자열)
    ]
