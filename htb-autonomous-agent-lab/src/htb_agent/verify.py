"""
verify — 증거 기반 성공 판정
==============================

`docs/EXPLOIT-LOOP.md` ⑤ 의 규칙을 코드로 강제한다.

**도구의 "success" 출력은 증거가 아니다.** 실패해도 종료코드 0 을 돌려주는
도구가 많고, 프롬프트처럼 보이는 문자열은 배너일 수도 있다. 그래서 이 모듈의
판정은 전부 **독립적인 재확인(probe)** 을 거친다. 익스플로잇 자신의 출력만
보고 `confirmed` 를 내는 경로는 `flag()` 하나뿐이며, 그것도 형식 검증 +
출처 경로 기록을 통과해야 한다.

판정 3종은 `attempt.py` 와 같다. 기본값이 `inconclusive` 인 것이 핵심이다 —
모르면 모른다고 적어야 맞는 접근면을 일찍 버리지 않는다.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Protocol

from .flag import scan as scan_flags
from .tools.runner import RunOutput

DEFAULT_PROBE_TIMEOUT = 15


class Probe(Protocol):
    """`ShellSession.run` 과 `Runner.run` 이 공통으로 만족하는 형태."""
    def run(self, command: str, timeout: int = ...) -> RunOutput: ...


# probe 는 객체(.run) 또는 호출가능 둘 다 받는다 — 호출측 편의
ProbeLike = Probe | Callable[..., RunOutput]


@dataclass
class Evidence:
    verdict: str                    # confirmed | refuted | inconclusive
    because: str                    # 항상 기록. refuted 면 특히 필수
    foothold: str | None = None     # confirmed 일 때 획득한 능력
    observed: str = ""              # 관측 요약 (원장용)
    probe_command: str = ""         # 무엇으로 확인했는지
    provenance: str = ""            # 플래그 획득 경로 (아래 FLAG_* 참조)

    @property
    def ok(self) -> bool:
        return self.verdict == "confirmed"


# 플래그 획득 경로 — ctf-abacus(2608.26237) 의 provenance 개념.
# "플래그가 나타났는가"가 아니라 "어떻게 도달했는가"가 결정적이다.
FLAG_GENUINE = "genuine"            # 익스플로잇(= 사전 Foothold) 이후 대상에서 관측
FLAG_UNDEMONSTRATED = "undemonstrated"   # 플래그는 나왔으나 선행 익스플로잇 증거 없음

# Foothold 문자열 접두사 규약. `Attempt` 는 confirmed 에 foothold 를 요구하므로
# '확인된 사실'도 foothold 칸에 들어간다 — 그걸 '획득한 접근 능력'과 섞으면
# 배너 하나 확인한 것이 접근 획득으로 보고되고(과장), provenance 의 genuine
# 판정까지 느슨해진다. 접두사로 구분한다.
FLAG_PREFIX = "flag:"
VERIFIED_PREFIX = "verified:"       # 증거로 확인된 '사실'(능력 아님)


def is_capability(foothold: str | None) -> bool:
    """실제로 획득한 접근 능력인가(셸·RCE·인증). 플래그·단순 확인은 아니다."""
    f = (foothold or "").strip()
    return bool(f) and not f.startswith((FLAG_PREFIX, VERIFIED_PREFIX))


def _call(probe: ProbeLike, command: str, timeout: int) -> RunOutput:
    fn = getattr(probe, "run", probe)
    return fn(command, timeout=timeout)


def _without_command(out: str, command: str) -> str:
    """에코된 명령'줄'만 걷어낸다 — 명령에 박힌 문자열을 '출력'으로 오인하지 않도록.

    단순 문자열 치환(`out.replace(command, "")`)은 양방향으로 틀린다:
      - **거짓 refuted**: 짧은 명령이 정상 출력 내부의 부분문자열을 파괴한다.
        `id` 를 걷어내면 `uid=0(root) gid=0(root)` → `u=0(root) g=0(root)` 가
        되어 `probe:id::uid=` 가 성공한 루트 셸을 반증으로 판정한다. 그 refuted 는
        접근면 소진 상한에 쌓여 **작동하는 경로를 버리게** 만든다.
      - **거짓 confirmed**: 프롬프트 접두사가 붙어 에코된 줄
        (`root@h:~# echo TOKEN`)을 남기면 토큰이 '되돌아온 것'으로 보인다.

    터미널 에코는 '줄' 단위로 돌아오므로, 줄이 명령과 같거나 명령으로 끝날 때만
    (= 프롬프트 + 에코) 걷어낸다. 출력 중간에 박힌 우연한 일치는 건드리지 않는다.
    """
    cmd = command.strip()
    if not cmd:
        return out
    kept: list[str] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if stripped == cmd:
            continue                                  # 순수 에코 줄
        if stripped.endswith(cmd) and len(stripped) > len(cmd):
            kept.append(stripped[: -len(cmd)])        # 프롬프트 + 에코 줄
            continue
        kept.append(line)
    return "\n".join(kept)


def _tail(text: str, n: int = 300) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else "…" + text[-n:]


def shell(probe: ProbeLike, foothold: str = "shell",
          echo_fmt: str = "echo {token}",
          timeout: int = DEFAULT_PROBE_TIMEOUT) -> Evidence:
    """셸 획득 판정 — 고유 난수 토큰을 보내고 그 토큰이 되돌아오는지 본다.

    프롬프트 모양·배너로는 판정하지 않는다. `echo_fmt` 는 대상 셸에 맞춰
    바꾼다(cmd.exe·제한 셸·리버스 셸 등에서 `echo` 가 다르게 동작할 수 있다).
    """
    token = secrets.token_hex(8)
    cmd = echo_fmt.format(token=token)
    out = _call(probe, cmd, timeout)

    if out.error:
        return Evidence("inconclusive", f"probe 실행 실패: {out.error}",
                        probe_command=cmd)
    if out.timed_out:
        return Evidence("inconclusive", f"probe 타임아웃({timeout}s) — 채널이 느린 것인지 "
                                        "죽은 것인지 구분 불가", probe_command=cmd)

    body = _without_command(out.stdout, cmd) + _without_command(out.stderr, cmd)
    if token in body:
        return Evidence("confirmed", f"토큰 {token} 반환 확인", foothold=foothold,
                        observed=_tail(body), probe_command=cmd)
    return Evidence("refuted", "probe 는 실행됐으나 토큰이 돌아오지 않음 "
                               "— 명령 실행 채널이 아님",
                    observed=_tail(body), probe_command=cmd)


def confirms(probe: ProbeLike, command: str, must_contain: str,
             foothold: str | None = None,
             timeout: int = DEFAULT_PROBE_TIMEOUT) -> Evidence:
    """일반 증거 확인 — 독립 명령 1개를 돌려 기대 표식이 나오는지 본다.

    `EXPLOIT-LOOP.md` ⑤ 의 '임의파일읽기'(내용을 아는 파일을 읽어 일치 확인)와
    '인증 성공'(인증이 필요한 동작을 실제로 수행) 둘 다 이 함수로 덮는다.
    """
    if not must_contain:
        return Evidence("inconclusive", "must_contain 미지정 — 확인할 표식이 없음",
                        probe_command=command)

    out = _call(probe, command, timeout)
    if out.error:
        return Evidence("inconclusive", f"probe 실행 실패: {out.error}",
                        probe_command=command)
    if out.timed_out:
        return Evidence("inconclusive", f"probe 타임아웃({timeout}s)",
                        probe_command=command)

    body = _without_command(out.stdout, command) + _without_command(out.stderr, command)
    if must_contain in body:
        return Evidence("confirmed", f"기대 표식 {must_contain!r} 관측",
                        foothold=foothold or f"verified: {command}",
                        observed=_tail(body), probe_command=command)
    return Evidence("refuted", f"probe 는 실행됐으나 기대 표식 {must_contain!r} 없음",
                    observed=_tail(body), probe_command=command)


def flag(command: str, output: str, earned: bool = False) -> Evidence:
    """플래그 판정 — `flag.py` 형식 검증 + 출처(명령) 기록 + **획득 경로**.

    못 찾은 경우는 `refuted` 가 아니라 `inconclusive` 다. 한 번의 출력에
    플래그가 없다는 것은 가설의 반증이 아니다.

    `earned` = 이 플래그 이전에 대상에서 '증명된 익스플로잇(Foothold)'이 있었는가.
    True 면 genuine-solve, False 면 undemonstrated — 플래그는 맞지만 그걸 읽을
    권한을 어떻게 얻었는지 증거가 없다(그냥 노출돼 있었거나, 추측/외부). 이 구분을
    기록해야 "플래그를 실제로 공략해 얻었다"를 정직하게 주장할 수 있다(룰 2-4).
    """
    hits = scan_flags(command, output)
    if not hits:
        return Evidence("inconclusive", "출력에서 플래그 형식을 찾지 못함",
                        observed=_tail(output), probe_command=command)
    h = hits[0]
    prov = FLAG_GENUINE if earned else FLAG_UNDEMONSTRATED
    note = ("선행 Foothold 있음 → genuine" if earned
            else "선행 익스플로잇 증거 없음 → undemonstrated(미증명)")
    return Evidence("confirmed",
                    f"{h.kind} 플래그 형식 검증 통과 (출처: {h.source}); {note}",
                    foothold=f"flag:{h.kind}", observed=h.value,
                    probe_command=command, provenance=prov)
