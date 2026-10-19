r"""
ShellSession — 지속 셸 세션 러너 (pexpect)
==========================================

`runner.SubprocessRunner` 의 구조적 한계를 제거한다.

| 한계 (SubprocessRunner)        | ShellSession                              |
|--------------------------------|-------------------------------------------|
| one-shot (`cd`·env 소실)       | 지속 bash 1개 — 작업디렉토리·변수 유지    |
| `shell=False` (파이프 불가)    | 실제 셸 — `\|` `>` `&&` `$()` 사용 가능     |
| pty 없음 (대화형 도구 불가)    | pty — nc·ssh·evil-winrm·gdb 상호작용      |
| 120s 고정 타임아웃             | 기본 300s + 백그라운드 작업(nmap -p- 등)  |

`Runner` 프로토콜(`run(command, timeout) -> RunOutput`)을 만족하므로
orchestrator 를 수정하지 않고 교체할 수 있다.

안전
----
실제 셸을 경유하므로 `command_validator`(문법·파괴명령)와 `scope_guard`
(대상 범위)를 **반드시 이 모듈 앞단에 두어야 한다**. 이 모듈은 검증을
수행하지 않으며, 검증을 대체하지도 않는다.

대화형 명령(`cat`·`read` 처럼 stdin 을 소비하는 것)은 `run()` 의 종료 마커를
삼켜버린다. 그런 명령은 `send_line()` + `expect()` 로 직접 다룬다.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field

from .runner import RunOutput

try:
    import pexpect
except ImportError:                                  # pragma: no cover
    pexpect = None                                   # type: ignore[assignment]


DEFAULT_TIMEOUT = 300          # 120s 는 `nmap -p-` 에 부족
SYNC_TIMEOUT = 10
RECOVER_TIMEOUT = 15

# set +m : 백그라운드 작업의 "[1] 12345" / "Done" 잡제어 메시지 억제
# stty -echo : 입력 에코가 출력에 섞이지 않게
_SETUP = (
    "set +m",
    "set +o history",
    "stty -echo 2>/dev/null",
    "unset PROMPT_COMMAND",
    "PS1=",
    "export TERM=dumb",
)


class SessionError(RuntimeError):
    """세션 생성·동기화·복구 실패."""


@dataclass
class BgJob:
    """백그라운드 작업 핸들."""
    name: str
    pid: int
    log: str
    command: str
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started


def _clean(out: str, command: str) -> str:
    """CR 정규화 + 에코된 명령줄 제거(stty -echo 실패 대비)."""
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    lines = out.split("\n")
    if lines and lines[0].strip() == command.strip():
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


class ShellSession:
    """지속 bash 세션. `Runner` 프로토콜 호환."""

    def __init__(self, shell: str = "/bin/bash", cwd: str | None = None,
                 env: dict[str, str] | None = None,
                 default_timeout: int = DEFAULT_TIMEOUT,
                 workdir: str = "/tmp/htb-agent") -> None:
        if pexpect is None:
            raise SessionError("pexpect 미설치 — pip install pexpect")
        self.default_timeout = default_timeout
        self.workdir = workdir
        self._shell, self._cwd, self._env = shell, cwd, env
        self.respawns = 0
        os.makedirs(workdir, exist_ok=True)
        self._bg: dict[str, BgJob] = {}
        self._spawn()

    # ── 내부 ──────────────────────────────────────────────────────────
    def _spawn(self) -> None:
        try:
            self.c = pexpect.spawn(
                self._shell, ["--norc", "--noprofile"], cwd=self._cwd, env=self._env,
                encoding="utf-8", codec_errors="replace", echo=False,
                timeout=self.default_timeout,
                dimensions=(100, 500),   # 줄바꿈으로 도구 출력이 깨지지 않게 넓게
            )
        except Exception as e:                       # pragma: no cover
            self.alive = False
            raise SessionError(f"셸 생성 실패: {e}") from e
        self.alive = True
        for line in _SETUP:
            self.c.sendline(line)
        self._sync()

    def _respawn(self) -> bool:
        """셸이 죽었을 때(EOF) 새 셸로 교체.

        무개입 운용에서 셸 사망은 런 전체 손실로 이어지므로 자동 복구한다.
        단, 작업디렉토리·환경변수·대화형 세션은 **복구되지 않는다**(호출측에 보고).
        """
        try:
            self.c.close(force=True)
        except Exception:                            # pragma: no cover
            pass
        try:
            self._spawn()
        except SessionError:
            return False
        self.respawns += 1
        return True

    @staticmethod
    def _mark() -> str:
        return "__HTBA" + uuid.uuid4().hex[:12] + "__"

    def _sync(self, timeout: int = SYNC_TIMEOUT) -> None:
        """셸이 입력을 받을 준비가 됐는지 마커로 확인."""
        m = self._mark()
        self.c.sendline(f"printf '%s\\n' {m}")
        try:
            self.c.expect_exact(m, timeout=timeout)
        except Exception as e:
            self.alive = False
            raise SessionError(f"셸 동기화 실패: {e}") from e

    def _recover(self, timeout: int = RECOVER_TIMEOUT) -> str:
        """Ctrl-C 후 셸을 재사용 가능 상태로. 반환: "" 성공 / 사유 실패.

        Ctrl-C 는 터미널 입력 큐를 함께 비우므로 미리 넣어둔 종료 마커는
        유실된다고 보고, **새 마커로** 동기화한다. 그래도 안 되면 셸을 교체한다.
        """
        try:
            self._sync(timeout=timeout)
            return ""
        except SessionError:
            pass
        if self._respawn():
            return "타임아웃 후 셸 교체 — 작업디렉토리·환경변수는 초기화됨"
        return "타임아웃 후 세션 복구 실패(재생성 필요)"

    # ── Runner 프로토콜 ───────────────────────────────────────────────
    def run(self, command: str, timeout: int | None = None) -> RunOutput:
        """명령 1건 실행. 종료코드까지 회수한다."""
        if not self.alive:
            return RunOutput(command, error="세션이 종료됨", returncode=-1)
        t = timeout or self.default_timeout
        m = self._mark()
        # 명령과 마커를 '별도 입력줄'로 보낸다 → `cmd &` 같은 형태도 깨지지 않음
        self.c.sendline(command)
        self.c.sendline(f"printf '%s%d\\n' {m} $?")
        try:
            self.c.expect(re.escape(m) + r"(\d+)", timeout=t)
        except pexpect.TIMEOUT:
            partial = _clean(self.c.before or "", command)
            self.c.sendintr()                        # Ctrl-C
            return RunOutput(command, stdout=partial, returncode=-1, timed_out=True,
                             error=self._recover())
        except pexpect.EOF:
            partial = _clean(self.c.before or "", command)
            note = ("셸이 종료됨(EOF) → 새 셸로 복구. 작업디렉토리·환경변수는 초기화됨"
                    if self._respawn() else "셸이 종료됨(EOF) → 복구 실패")
            return RunOutput(command, stdout=partial, error=note, returncode=-1)
        return RunOutput(command, stdout=_clean(self.c.before or "", command),
                         returncode=int(self.c.match.group(1)))

    # ── 대화형 (리버스 셸·ssh·evil-winrm·gdb) ────────────────────────
    def send_line(self, data: str) -> None:
        self.c.sendline(data)

    def send(self, data: str) -> None:
        self.c.send(data)

    def sendintr(self) -> None:
        """Ctrl-C."""
        self.c.sendintr()

    def expect(self, patterns: str | list[str], timeout: int | None = None) -> int:
        """패턴 대기. 일치한 인덱스를 돌려준다(pexpect 규약)."""
        return self.c.expect(patterns, timeout=timeout or self.default_timeout)

    @property
    def before(self) -> str:
        return _clean(self.c.before or "", "")

    # ── 백그라운드 (긴 스캔을 돌리면서 다른 단계 진행) ───────────────
    def start_background(self, command: str, name: str | None = None) -> BgJob:
        name = name or f"job{len(self._bg) + 1}"
        script = os.path.join(self.workdir, f"{name}.sh")
        log = os.path.join(self.workdir, f"{name}.log")
        # ponytail: 로컬 Kali 세션 전제로 스크립트를 파이썬이 직접 쓴다(인용 지옥 회피).
        #           원격 셸로 확장할 땐 heredoc 전송으로 교체.
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n" + command + "\n")
        out = self.run(f"nohup bash {script} > {log} 2>&1 & echo $!", timeout=20)
        tail = out.stdout.strip().split()
        if not tail or not tail[-1].isdigit():
            raise SessionError(f"백그라운드 시작 실패: {out.stdout!r} / {out.error}")
        job = BgJob(name=name, pid=int(tail[-1]), log=log, command=command)
        self._bg[name] = job
        return job

    def bg_running(self, job: BgJob) -> bool:
        return self.run(f"kill -0 {job.pid} 2>/dev/null", timeout=15).returncode == 0

    def bg_output(self, job: BgJob, tail: int = 200) -> str:
        return self.run(f"tail -n {tail} {job.log} 2>/dev/null", timeout=20).stdout

    def bg_kill(self, job: BgJob) -> None:
        # ponytail: 자식까지 확실히 정리하려면 프로세스 그룹 kill 로 승격할 것.
        self.run(f"pkill -P {job.pid} 2>/dev/null; kill {job.pid} 2>/dev/null; true",
                 timeout=15)

    def bg_jobs(self) -> list[BgJob]:
        return list(self._bg.values())

    # ── 종료 ─────────────────────────────────────────────────────────
    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            self.c.sendline("exit")
            self.c.close(force=True)
        except Exception:                            # pragma: no cover
            pass

    def __enter__(self) -> "ShellSession":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
