"""로컬 Ollama 백엔드 — 오프라인·무과금. 표준 라이브러리만 사용.

로컬 모델이 Claude 를 대신할 때 가장 조용히 망가지는 지점들을 막는다:

  - **num_ctx 를 명시한다.** 생략하면 서버 기본 컨텍스트(버전·VRAM 에 따라 수 k 토큰)가
    쓰이고, 프롬프트가 넘치면 **오류 없이 앞부분(= 시스템 프롬프트)이 잘린다.** 형식 규칙이
    사라진 모델은 그럴듯한 쓰레기를 낸다. 창은 기본 8192, `HTB_OLLAMA_NUM_CTX` 로 조정.
  - 응답의 `prompt_eval_count` 가 창에 거의 찼으면 `detail='ctx_full'` 로 알려, 라우터가
    다음 호출의 컨텍스트 예산을 줄이게 한다.
  - 모델명은 하드코딩하지 않는다: `HTB_OLLAMA_CHEAP|STANDARD|STRONG` 환경변수로 '소넷급'
    (예: 32B~70B)을 지정한다. 파라미터 수로 능력 등급을 추정해 프롬프트 예산을 맞춘다
    (`tiering.profile_for`).
  - 온도는 낮게(형식 준수↑). 토큰 수·종료 사유를 돌려줘 비용/잘림 집계가 로컬에서도 맞는다.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from .base import LLMProvider, LLMResponse, Tier

_ENV = {Tier.CHEAP: "HTB_OLLAMA_CHEAP", Tier.STANDARD: "HTB_OLLAMA_STANDARD",
        Tier.STRONG: "HTB_OLLAMA_STRONG"}
DEFAULT_NUM_CTX = 8192


class OllamaProvider(LLMProvider):
    name = "ollama"
    models = {
        Tier.CHEAP: "llama3.1:8b",
        Tier.STANDARD: "llama3.1:8b",
        Tier.STRONG: "llama3.1:70b",
    }

    def __init__(self, host: str | None = None, models: dict | None = None,
                 num_ctx: int | None = None, temperature: float = 0.2):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        from_env = {t: os.environ[v] for t, v in _ENV.items() if os.environ.get(v)}
        self.models = {**self.models, **from_env, **(models or {})}
        self.num_ctx = int(num_ctx or os.environ.get("HTB_OLLAMA_NUM_CTX") or DEFAULT_NUM_CTX)
        self.temperature = temperature

    def num_ctx_for(self, tier: Tier) -> int | None:
        return self.num_ctx

    def available(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=3) as r:
                r.read()
            return True, "ok"
        except (urllib.error.URLError, OSError) as e:
            return False, f"Ollama 연결 실패({self.host}): {e}"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        model = self.model_for(tier)
        payload = json.dumps({
            "model": model, "system": system, "prompt": user, "stream": False,
            "options": {"num_predict": max_tokens, "num_ctx": self.num_ctx,
                        "temperature": self.temperature},
        }).encode()
        req = urllib.request.Request(self.host + "/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
        pe = int(data.get("prompt_eval_count") or 0)
        ev = int(data.get("eval_count") or 0)
        finish, notes = "ok", []
        if data.get("done_reason") == "length":
            finish = "truncated"
            notes.append("num_predict")
        # 창이 거의 찼다 = 프롬프트가 잘렸을 가능성(충분조건일 뿐, 놓칠 수는 있다)
        if pe >= int(self.num_ctx * 0.97):
            notes.append("ctx_full")
        return LLMResponse(data.get("response", ""), model, prompt_tokens=pe,
                           completion_tokens=ev, finish=finish, detail=" ".join(notes))
