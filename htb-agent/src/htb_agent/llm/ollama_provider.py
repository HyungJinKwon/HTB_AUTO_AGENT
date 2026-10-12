"""로컬 Ollama 백엔드 — 오프라인·무과금. 표준 라이브러리만 사용."""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request

from .base import LLMProvider, LLMResponse, Tier


class OllamaProvider(LLMProvider):
    name = "ollama"
    models = {
        Tier.CHEAP: "qwen2.5:7b",
        Tier.STANDARD: "qwen2.5:7b",
        Tier.STRONG: "llama3.3:70b",
    }

    def __init__(self, host: str | None = None, models: dict | None = None):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.installed: list[str] = []   # /api/tags 로 확인한 설치 모델(available() 이 채움)
        self.models = dict(self.models)
        # 초보자 편의: OLLAMA_MODEL 하나로 전 티어를 설치된 모델로 덮어쓴다.
        env_model = os.environ.get("OLLAMA_MODEL")
        if env_model:
            self.models = {t: env_model for t in self.models}
        if models:
            self.models = {**self.models, **models}
        # [재시도/백오프] Ollama 는 재시도가 없어 일시 네트워크 블립(연결거부·타임아웃) 1회가
        # 하드 오류로 집계됐다(→ 서킷브레이커 조기 트립). 전이성 오류만 지터드 지수백오프로
        # 소수 재시도(상한으로 예산 보호). sleep 은 주입 가능(테스트는 no-op).
        self._retries = 2                 # 추가 재시도 횟수(총 1+2회)
        self._backoff_base = 0.4          # 초
        self._backoff_cap = 4.0           # 재시도 간 최대 대기(예산 보호)
        self._sleep = time.sleep
        self.slept_sec = 0.0              # [T2-e] 재시도 백오프로 '대기'한 누적 시간(예산서 제외용)

    def available(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=3) as r:
                data = json.loads(r.read() or b"{}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, f"Ollama 연결 실패({self.host}): {e}"
        self.installed = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]
        if data.get("models") is not None and not self.installed:
            return False, "Ollama 에 설치된 모델 없음(ollama pull qwen2.5:7b)"
        return True, "ok"

    def model_for(self, tier: Tier) -> str:
        """티어 모델이 설치돼 있지 않으면 설치된 다른 티어 모델 → 아무 설치 모델 순으로 대체.
        (예: strong=llama3.3:70b 미설치인데 7b 만 있으면 7b 사용 — 없는 모델 호출로 항상 실패하던 문제)"""
        want = super().model_for(tier)
        if not self.installed or self._has(want):
            return want
        for t in (Tier.STANDARD, Tier.CHEAP, Tier.STRONG):
            alt = self.models.get(t, "")
            if alt and self._has(alt):
                return alt
        return self.installed[0]

    def _has(self, name: str) -> bool:
        base = name if ":" in name else name + ":latest"
        return name in self.installed or base in self.installed

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024,
                 tools: "list | None" = None) -> LLMResponse:
        # Ollama /api/generate 는 Anthropic 식 tool use 가 없다 → tools 무시, 텍스트로 답하고
        # 라우터가 텍스트(JSON/라인) 파싱으로 폴백한다.
        model = self.model_for(tier)
        payload = json.dumps({
            "model": model, "system": system, "prompt": user,
            "stream": False, "options": {"num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(self.host + "/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"})
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                return self._once(req, model)
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    raise                 # 클라이언트 오류(모델 부재 등) — 재시도 무의미
                last = e
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
                last = e                  # 연결거부·타임아웃·소켓·깨진 JSON = 전이성 → 재시도
            if attempt < self._retries:
                delay = self._backoff(attempt)
                self.slept_sec += delay      # [T2-e] 대기 시간 누적(시간 예산서 제외)
                self._sleep(delay)
                continue
            raise last                    # 재시도 소진 — 마지막 오류를 올린다(라우터가 폴백/집계)
        raise last if last else RuntimeError("ollama: unreachable")  # pragma: no cover

    def _once(self, req: "urllib.request.Request", model: str) -> LLMResponse:
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
        return LLMResponse(data.get("response", ""), model)

    def _backoff(self, attempt: int) -> float:
        """지터드 지수백오프(상한). attempt 0,1,… → base*2^n + 소량 지터, cap 으로 제한."""
        return min(self._backoff_cap, self._backoff_base * (2 ** attempt)) + random.uniform(0, 0.2)
