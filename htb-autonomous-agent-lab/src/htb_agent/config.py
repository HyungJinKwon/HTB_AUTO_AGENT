"""
Config Loader — 파일 기반 설정 (JSON / YAML)
=============================================

CLI/환경변수 외에 설정 파일로 기본값을 관리한다. 우선순위는
**CLI > 설정파일 > 내장 기본값**. 외부 의존성 없이 JSON 을 지원하고,
YAML 은 pyyaml 이 있을 때만(없으면 명확히 안내).
"""

from __future__ import annotations

import json
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass
class Config:
    allowed_ranges: list[str] | None = None
    attacker_ips: list[str] | None = None
    llm_backend: str | None = None
    llm_tier: str | None = None
    max_attempts: int | None = None
    max_enum: int | None = None
    max_llm: int | None = None
    max_rounds: int | None = None
    token_budget: int | None = None
    knowledge_dir: str | None = None
    state_dir: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        d = d or {}
        llm = d.get("llm", {}) or {}
        return cls(
            allowed_ranges=d.get("allowed_ranges"),
            attacker_ips=d.get("attacker_ips"),
            llm_backend=llm.get("backend", d.get("llm_backend")),
            llm_tier=llm.get("tier", d.get("llm_tier")),
            max_attempts=d.get("max_attempts"),
            max_enum=d.get("max_enum"),
            max_llm=d.get("max_llm"),
            max_rounds=d.get("max_rounds"),
            token_budget=d.get("token_budget"),
            knowledge_dir=d.get("knowledge_dir", d.get("knowledge")),
            state_dir=d.get("state_dir"),
        )


def _read_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise ConfigError(f"설정 파일을 열 수 없음: {path} ({e})") from e
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise ConfigError(
                "YAML 설정은 pyyaml 필요 — 'pip install pyyaml' 하거나 JSON(.json) 사용"
            ) from e
        try:
            return yaml.safe_load(text) or {}
        except yaml.YAMLError as e:  # type: ignore
            raise ConfigError(f"YAML 파싱 실패: {e}") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"JSON 파싱 실패: {e}") from e


def load_config(path: str) -> Config:
    data = _read_file(path)
    if not isinstance(data, dict):
        raise ConfigError("설정 최상위는 매핑(객체)이어야 합니다.")
    return Config.from_dict(data)


def pick(cli_value, config_value, default):
    """우선순위 해소: CLI(None 아님) > config(None 아님) > 기본값."""
    if cli_value is not None:
        return cli_value
    if config_value is not None:
        return config_value
    return default
