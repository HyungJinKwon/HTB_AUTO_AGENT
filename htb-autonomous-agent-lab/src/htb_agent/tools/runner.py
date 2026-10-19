"""
Runner — 명령 실행 추상화 (주입식)
====================================

실제 Kali 에서는 subprocess 로 도구를 실행하고(SubprocessRunner),
테스트/컨테이너에서는 가짜 러너(FakeRunner)로 동일 인터페이스를 대체한다.
→ 네트워크/도구 없이도 상위 로직(폴백 체인 등)을 검증할 수 있다.

안전: SubprocessRunner 는 shell=False(쉘 비경유)로 실행해 쉘 인젝션을 차단한다.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass
class RunOutput:
    command: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    error: str = ""          # 실행 자체 실패(바이너리 없음/파싱오류 등)

    @property
    def launched(self) -> bool:
        return not self.error


class Runner(Protocol):
    def run(self, command: str, timeout: int = 120) -> RunOutput: ...


class SubprocessRunner:
    """실제 Kali 용. shell 비경유(shell=False)."""

    def run(self, command: str, timeout: int = 120) -> RunOutput:
        try:
            args = shlex.split(command)
        except ValueError as e:
            return RunOutput(command, error=f"명령 파싱 실패: {e}", returncode=-1)
        if not args:
            return RunOutput(command, error="빈 명령", returncode=-1)
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return RunOutput(command, p.stdout, p.stderr, p.returncode)
        except FileNotFoundError:
            return RunOutput(command, error=f"'{args[0]}' 미설치", returncode=-1)
        except subprocess.TimeoutExpired as e:
            return RunOutput(command, e.stdout or "", e.stderr or "",
                             returncode=-1, timed_out=True)
        except OSError as e:
            return RunOutput(command, error=f"실행 오류: {e}", returncode=-1)


class FakeRunner:
    """테스트용. responder(command)->RunOutput|str 로 응답을 흉내낸다."""

    def __init__(self, responder: Callable[[str], "RunOutput | str"]):
        self._responder = responder
        self.calls: list[str] = []

    def run(self, command: str, timeout: int = 120) -> RunOutput:
        self.calls.append(command)
        out = self._responder(command)
        if isinstance(out, str):
            return RunOutput(command, stdout=out)
        return out
