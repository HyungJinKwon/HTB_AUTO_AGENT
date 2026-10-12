"""
auto-relaunch — 크래시/예외 시 저장 지점부터 재시작 (redcat2 run.sh MAX_RESTARTS 이식)
========================================================================================

무인 자율 실행 중 예기치 못한 예외로 프로세스가 죽으면, 저장된 상태(StateStore)에서 `--resume`
으로 이어 재시작한다. 우리 아키텍처는 LLM 컨텍스트를 누적하지 않아(재조립) '컨텍스트 오버플로'
크래시는 없지만, 드문 미처리 예외·일시 환경 오류에 대한 완주 보조로 둔다.

안전·경계:
  · **기본 OFF**(max_restarts=0) — 버그를 재시작으로 가리지 않도록 opt-in(`--max-restarts`).
  · 사용자 중단(KeyboardInterrupt)·SystemExit 은 **재시작하지 않고 전파**(의도적 종료 존중).
  · 재시작 시 `orchestrator.resume=True` → run() 이 저장 지점부터 복원(진행 유실 최소화).
  · 상한(max_restarts)으로 bound — 결정적 크래시는 N회 후 예외를 올린다(무한루프 없음).
"""
from __future__ import annotations

import time
from typing import Callable


def run_with_relaunch(orchestrator, max_restarts: int = 0, *,
                      log: Callable[[int, int, Exception], None] | None = None,
                      sleep: Callable[[float], None] = time.sleep):
    """orchestrator.run() 을 호출하되, 미처리 예외 시 저장 지점부터 최대 max_restarts 회 재시작.
    반환: run() 의 반환값(OrchestrationReport). KeyboardInterrupt/SystemExit 은 즉시 전파."""
    attempt = 0
    while True:
        try:
            return orchestrator.run()
        except (KeyboardInterrupt, SystemExit):
            raise                      # 의도적 종료 — 재시작 안 함
        except Exception as e:         # noqa: BLE001 — 무인 완주 보조(상한 bound)
            if attempt >= max_restarts:
                raise                  # 재시작 소진 — 마지막 예외 전파
            attempt += 1
            orchestrator.resume = True  # 다음 시도는 저장 지점부터 이어서
            if log is not None:
                log(attempt, max_restarts, e)
            sleep(min(2.0 * attempt, 10.0))   # 가벼운 백오프(상한 10초)
