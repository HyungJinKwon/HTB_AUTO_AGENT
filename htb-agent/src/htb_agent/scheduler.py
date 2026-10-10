"""의존 선언형 스테이지 스케줄러 (S3).

구조 감사 지적: 결정적 소비 스테이지(제품 핑거프린트 → 버전 프로브 → 익스 조회 → 웹 비밀)의
'언제·어떤 순서로·재실행 여부'가 각 스테이지 내부의 ``_*_probed`` 가드와 호출부 하드코딩
순서에 흩어져 있어 ① 순서가 깨지기 쉽고(S1 이 수동 재배치로 임시 교정) ② 종료 조건을
추론하기 어렵다. 이 모듈은 스케줄링을 **선언적 1급 객체**로 끌어올린다.

각 스테이지는 다음을 선언한다.

* ``ready()``  — 전제(월드 상태)가 충족돼 돌 수 있는가.
* ``key()``    — '소비하는' 월드 상태의 서명. 이 값이 바뀌면(=입력이 자라면) 재실행 대상.
* ``run()``    — 부수효과(스테이지 본체 호출). 멱등은 스테이지 가드로도 이중 보장.

스케줄러는 선언 순서(생산자 → 소비자)대로 훑으며 ``ready`` 하고 ``key`` 가 지난 실행 이후
바뀐('dirty') 스테이지만 실행한다. 한 패스에서 아무것도 안 돌면 **지역 고정점**이므로 멈춘다.
스테이지 실행이 다른(뒤의) 스테이지의 입력을 키우면 같은 패스 또는 다음 패스에서 그 소비자가
dirty 로 잡혀 이어 돈다 → 의존 체인이 순서대로 완주. ``_seen`` 을 호출 간 유지하면 스윕을
가로질러서도 '입력이 바뀐 스테이지만' 다시 돈다(기존 ``_*_probed`` 전역 멱등과 동일 의미).

순수 로직(네트워크·LLM 없음)이라 단위 테스트로 순서·재실행·고정점·종료를 고정한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

__all__ = ["Stage", "StageScheduler"]


@dataclass
class Stage:
    """스케줄 1단위. ``run`` 은 바인딩된 스테이지 호출, ``ready``/``key`` 는 월드 상태 조회."""

    name: str
    run: Callable[[], None]
    ready: Callable[[], bool]
    key: Callable[[], tuple]


@dataclass
class StageScheduler:
    """의존 선언형 소비 스테이지 스케줄러.

    ``stages`` 는 생산자가 소비자보다 앞서도록 선언 순서로 둔다. ``_seen`` 은 스테이지별 마지막
    실행 시점의 ``key`` 를 기억해, 입력이 바뀐 스테이지만 다시 돌게 한다(선언적 멱등).
    """

    stages: list[Stage]
    max_passes: int = 6
    _seen: dict[str, tuple] = field(default_factory=dict)

    def run_to_fixpoint(self, should_stop: Callable[[], bool] | None = None) -> int:
        """ready & dirty 스테이지를 선언 순서로, 패스가 '무실행'이 될 때까지 반복 실행한다.

        한 스테이지를 실행하면 그 시점의 ``key``(입력 서명)를 ``_seen`` 에 기록한다. 실행이 자신의
        입력을 다시 바꾸면 다음 패스에서 또 dirty 로 잡혀 재실행되므로, 반복은 '입력이 더는 바뀌지
        않는' 고정점에서 자연 종료한다. ``max_passes`` 는 폭주 방지 안전 상한(의존 깊이보다 넉넉).
        ``should_stop`` 이 True 면 즉시 중단(목표 달성·시간 예산 소진 등). 실행한 스테이지 수 반환.
        """
        stop = should_stop or (lambda: False)
        fired = 0
        for _ in range(max(1, self.max_passes)):
            fired_this_pass = 0
            for st in self.stages:
                if stop():
                    return fired
                if not st.ready():
                    continue
                k = st.key()
                if self._seen.get(st.name) == k:
                    continue  # 입력 불변 → 건너뜀(선언적 멱등)
                # 실행을 '촉발한' 입력 서명을 먼저 기록 — 실행이 자기 입력을 또 바꾸면
                # 다음 패스에서 새 서명으로 다시 dirty 가 돼 이어 돈다(고정점까지).
                self._seen[st.name] = k
                st.run()
                fired += 1
                fired_this_pass += 1
            if fired_this_pass == 0:
                break  # 지역 고정점 — 더 돌 게 없음
        return fired

    def reset(self) -> None:
        """실행 이력 초기화 — 모든 스테이지를 다시 '최초 실행 대상'으로 되돌린다(테스트·재개용)."""
        self._seen.clear()
