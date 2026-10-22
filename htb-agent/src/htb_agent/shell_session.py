"""발판 셸 세션 추상화 (B단계) — '획득한 셸'을 채널 종류와 무관하게 다루는 공통 인터페이스.

자동 루트 실패의 근본 원인은 '실제 공격 경로(웹 RCE→셸)를 태울 발판 채널 부재'였다.
이 모듈은 그 채널을 추상화한 `ShellSession` 과, 가장 흔한 발판인 **리버스셸 수신 세션**의
뼈대를 제공한다.

안전 경계(불변):
  · 이 모듈은 **소켓 I/O·원격 명령 실행을 직접 하지 않는다.** 실제 송수신은 호출측이 주입하는
    `transport`(또는 `run_fn`) 콜러블이 담당한다 — 그 콜러블(소켓 accept/recv/send 루프)이
    RCE 실행 표면이다. 기본 구현은 `shell_transport.py`(내장, 옵트인·3관문 하)에 있고,
    테스트는 가짜 transport 를 주입한다.
  · 본 모듈이 하는 일: 세션 상태 관리, 리스너/페이로드 **명령 문자열 생성**, 명령 프레이밍
    (완료 마커로 출력 경계 잡기)·마커 제거 — 전부 문자열·상태 로직(생성 전용).
  · transport 미주입 세션은 `alive=False` 이며 `run()` 은 명확한 오류로 거부한다(섣부른 실행 방지).
"""
from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum


class ShellState(Enum):
    INIT = "init"              # 생성됨(아직 연결/리스닝 전)
    LISTENING = "listening"    # 리스너 대기 중(리버스셸)
    CONNECTED = "connected"    # 셸 확보 — run() 가능
    CLOSED = "closed"          # 종료됨


class ShellSession(ABC):
    """획득한 셸에 '한 줄 명령'을 실행하고 출력을 돌려주는 공통 인터페이스.
    채널(SSH one-shot·리버스셸·웹RCE)마다 구현이 달라도 orchestrator 는 동일하게 다룬다."""

    kind: str = "shell"

    @property
    @abstractmethod
    def alive(self) -> bool:
        """지금 명령을 보낼 수 있는 상태면 True."""

    @abstractmethod
    def run(self, cmd: str) -> str:
        """셸에서 명령 한 줄 실행 → 출력(문자열) 반환. 실제 실행은 구현/주입 콜러블의 몫."""

    def close(self) -> None:
        """세션 종료(기본: no-op)."""


class CommandRunnerSession(ShellSession):
    """one-shot 러너 기반 세션(SSH 등) 어댑터 — 상태 없는 채널을 세션 인터페이스로 감싼다.

    `wrap(cmd)` 로 원격 실행 명령을 만들고(예: SSHTargetShell.command), `run_fn(wrapped)` 로
    실행해 출력을 받는다. 두 콜러블 모두 호출측 주입 — 이 클래스는 조합만 한다(생성 전용).
    SSH 는 매 호출 재인증되므로 상태 없이도 '세션처럼' 동작한다."""

    kind = "command-runner"

    def __init__(self, run_fn: Callable[[str], str],
                 wrap: Callable[[str], str] | None = None, label: str = "ssh") -> None:
        self._run_fn = run_fn
        self._wrap = wrap or (lambda c: c)
        self.kind = f"command-runner:{label}"
        self._closed = False

    @property
    def alive(self) -> bool:
        return not self._closed

    def run(self, cmd: str) -> str:
        if self._closed:
            raise RuntimeError("세션이 이미 종료됨")
        return self._run_fn(self._wrap(cmd))

    def close(self) -> None:
        self._closed = True


def frame_command(cmd: str, marker: str) -> str:
    """리버스셸처럼 '명령 경계'가 없는 채널용 — 명령 뒤에 완료 마커와 종료코드를 붙여
    출력의 끝을 인식할 수 있게 한다. 문자열 생성만(실행 아님)."""
    return f"{cmd}; echo {marker}$?"


_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_marker(output: str, marker: str) -> tuple[str, int | None]:
    """frame_command 로 감싼 출력에서 본문과 종료코드를 분리한다(마커 줄 제거).
    마커가 없으면(아직 미완/프롬프트) 전체 본문과 None. 순수 파싱."""
    clean = _ANSI.sub("", output or "")
    m = re.search(re.escape(marker) + r"(\d+)", clean)
    if not m:
        return clean.strip(), None
    body = clean[:m.start()]
    # 본문 끝의 마커 echo 명령 잔재 줄 정리
    body = re.sub(r"(?m)^.*echo\s+" + re.escape(marker) + r".*$", "", body)
    return body.strip(), int(m.group(1))


class ReverseShellSession(ShellSession):
    """리버스셸 수신 세션 — 리스너/페이로드 생성 + 상태 관리 + 명령 프레이밍을 제공한다.

    실제 소켓 accept/recv/send 는 **주입된 `transport(framed_cmd) -> raw_output`** 이 담당한다
    (= RCE 실행 표면, 사용자 구현). transport 미주입이면 '대기(LISTENING)' 상태로 두고 run()
    을 거부한다. 이 클래스 자체는 소켓을 열지 않는다(생성 전용)."""

    kind = "reverse-shell"

    def __init__(self, lhost: str, lport: int,
                 transport: Callable[[str], str] | None = None) -> None:
        self.lhost = lhost
        self.lport = int(lport)
        self._transport = transport
        self._marker = "__HTBDONE_" + uuid.uuid4().hex[:8] + "_"
        self.state = ShellState.CONNECTED if transport else ShellState.LISTENING
        self.last_rc: int | None = None

    @property
    def alive(self) -> bool:
        return self.state == ShellState.CONNECTED and self._transport is not None

    def listener_command(self) -> str:
        """콜백을 받을 리스너 명령(문자열 생성). 사람이 미리 띄워 두거나 사용자 코드가 실행."""
        return f"nc -lvnp {self.lport}"

    def payloads(self, flavors: list[str] | None = None) -> list:
        """이 세션으로 콜백을 유도할 리버스셸 페이로드 목록(revshell 재사용, 문자열 생성)."""
        from .revshell import generate
        return generate(self.lhost, self.lport, only=flavors)

    def attach(self, transport: Callable[[str], str]) -> None:
        """콜백 수신 후, 실제 송수신 콜러블을 주입해 세션을 CONNECTED 로 전이(사용자가 호출)."""
        self._transport = transport
        self.state = ShellState.CONNECTED

    def run(self, cmd: str) -> str:
        if self._transport is None:
            raise RuntimeError(
                "리버스셸 수신 transport 미주입 — 소켓 accept/recv/send 는 사용자 구현을 "
                "attach() 로 주입해야 함(RCE 실행 표면). listener_command()/payloads() 로 준비 후 연결.")
        if self.state == ShellState.CLOSED:
            raise RuntimeError("세션이 이미 종료됨")
        raw = self._transport(frame_command(cmd, self._marker))
        body, rc = strip_marker(raw, self._marker)
        self.last_rc = rc
        return body

    def close(self) -> None:
        self.state = ShellState.CLOSED


class WebRceSession(ShellSession):
    """웹 RCE 명령 채널 세션 (C단계) — PoC 가 노출한 'cmd= 엔드포인트'로 임의 명령을 실행하는
    발판. 웹 RCE 는 SSH user:pass 가 아니라 www-data 코드실행을 주는, 머신형 공략의 흔한 경로다.

    실제 HTTP 요청은 **주입된 `http_fn(spec) -> raw_response`** 가 수행한다(= RCE 실행 표면,
    사용자 구현). 이 클래스는 요청 사양(method·url·cmd 주입 위치)과 명령 프레이밍·출력 파싱만
    만든다(생성 전용 — HTTP 라이브러리 미임포트). http_fn 미주입이면 run() 을 거부한다."""

    kind = "web-rce"

    def __init__(self, url: str, cmd_param: str, method: str = "GET",
                 inject: str = "query",
                 http_fn: Callable[[dict], str] | None = None,
                 extra_params: dict | None = None) -> None:
        if inject not in ("query", "body", "header"):
            raise ValueError("inject 는 query/body/header 중 하나")
        self.url = url
        self.cmd_param = cmd_param
        self.method = method.upper()
        self.inject = inject
        self._http_fn = http_fn
        self._extra = dict(extra_params or {})
        self._marker = "__HTBWEB_" + uuid.uuid4().hex[:8] + "_"
        self.state = ShellState.CONNECTED if http_fn else ShellState.INIT
        self.last_rc: int | None = None

    @property
    def alive(self) -> bool:
        return self.state == ShellState.CONNECTED and self._http_fn is not None

    def build_request(self, cmd: str) -> dict:
        """명령을 지정 위치(query/body/header)에 넣은 HTTP 요청 사양을 만든다(생성 전용).
        http_fn 이 이 dict 를 받아 실제 요청을 보낸다. 명령 자체는 호출측(run)에서 프레이밍됨."""
        spec: dict = {"method": self.method, "url": self.url,
                      "params": {}, "data": {}, "headers": {}}
        if self.inject == "query":
            spec["params"][self.cmd_param] = cmd
            spec["params"].update(self._extra)
        elif self.inject == "body":
            spec["data"][self.cmd_param] = cmd
            spec["data"].update(self._extra)
        else:  # header
            spec["headers"][self.cmd_param] = cmd
            spec["params"].update(self._extra)
        return spec

    def attach(self, http_fn: Callable[[dict], str]) -> None:
        """실제 HTTP 수행 콜러블을 주입해 CONNECTED 로 전이(사용자가 호출 — RCE 실행 표면)."""
        self._http_fn = http_fn
        self.state = ShellState.CONNECTED

    def run(self, cmd: str) -> str:
        if self._http_fn is None:
            raise RuntimeError(
                "웹 RCE http_fn 미주입 — 실제 HTTP 요청은 사용자 구현을 attach() 로 주입해야 함"
                "(RCE 실행 표면). build_request() 로 요청 사양만 생성 가능.")
        if self.state == ShellState.CLOSED:
            raise RuntimeError("세션이 이미 종료됨")
        spec = self.build_request(frame_command(cmd, self._marker))
        raw = self._http_fn(spec)
        body, rc = strip_marker(raw, self._marker)
        self.last_rc = rc
        return body

    def fire(self, cmd: str) -> str:
        """프레이밍/완료대기 없이 명령을 '쏘기만' 한다(fire-and-forget). 리버스셸 트리거처럼
        응답을 기다릴 필요가 없는(또는 응답이 영영 안 오는) 명령용. http_fn 미주입/요청오류면
        조용히 '' 반환(실행 표면 degrade — 호출측이 리스너 수신으로 성립을 판정)."""
        if self._http_fn is None:
            return ""
        try:
            return self._http_fn(self.build_request(cmd)) or ""
        except Exception:   # noqa: BLE001 — fire-and-forget: 연결거부/타임아웃 삼키고 degrade
            return ""

    def close(self) -> None:
        self.state = ShellState.CLOSED
