"""Centralized config — load tất cả env var một lần ở đây (S0.2 / F.4).

Mỗi module chỉ `from src.config import <tên>` thay vì đọc `os.getenv` rải rác.
Validate sớm (ConfigError raise khi thiếu biến bắt buộc), IDE autocompletion.

`pydantic-settings` đọc từ env ưu tiên và `.env` (cần set `env_file=".env"`).
Mặc định KHÔNG đọc `.env` để tránh surprise — caller chọn file qua
`Settings(_env_file=".env")` nếu cần (xem `load_settings()`).

Backward compat: các module vẫn có thể đọc trực tiếp `os.getenv("FOO")` — không
bắt buộc dùng config này. Chỉ recommend cho module mới.
"""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Neo4jConfig(BaseSettings):
    """Config cho Neo4j driver — 3 biến: URI, USER, PASSWORD (optional)."""

    model_config = SettingsConfigDict(
        env_prefix="NEO4J_",
        env_file=None,  # không đọc .env mặc định — xem load_settings()
        extra="ignore",
    )

    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str | None = None  # None = no-auth (NEO4J_AUTH=none demo local)

    @property
    def auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.password else None


class OpenSearchConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OPENSEARCH_",
        env_file=None,
        extra="ignore",
    )

    host: str = "localhost"
    port: int = 9200


class LLMConfig(BaseSettings):
    """Config cho LLM gateway OpenAI-compatible (Text2Cypher)."""

    model_config = SettingsConfigDict(
        env_file=None,
        extra="ignore",
    )

    api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    base_url: str | None = Field(default=None, validation_alias="OPENAI_BASE_URL")
    model: str | None = Field(default=None, validation_alias="TEXT2CYPHER_MODEL")

    @field_validator("api_key", "base_url", "model", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        """Coerce chuỗi rỗng (vd env `OPENAI_API_KEY=`) thành None — phân biệt
        "chưa set" vs "set thành rỗng". Caller chỉ cần check `is None`."""
        if v == "":
            return None
        return v


class NVDConfig(BaseSettings):
    """NVD API key (optional — không có key thì self-throttle 6s/CVE)."""

    model_config = SettingsConfigDict(
        env_prefix="NVD_",
        env_file=None,
        extra="ignore",
    )

    api_key: str | None = None


class TestConfig(BaseSettings):
    """Env cho integration test (gate destructive tests)."""

    model_config = SettingsConfigDict(
        env_prefix="ALLOW_",
        env_file=None,
        extra="ignore",
    )

    destructive_tests: bool = False  # ALLOW_DESTRUCTIVE_TESTS=1 → True


class Settings:
    """Container gom tất cả config — caller dùng `load_settings()`."""

    def __init__(self) -> None:
        self.neo4j = Neo4jConfig()
        self.opensearch = OpenSearchConfig()
        self.llm = LLMConfig()
        self.nvd = NVDConfig()
        self.test = TestConfig()


@lru_cache(maxsize=4)
def load_settings(env_file: str | None = None) -> Settings:
    """Đọc config 1 lần (cache theo env_file path).

    Args:
        env_file: đường dẫn .env để load (vd `.env`). None = đọc env trực tiếp,
            KHÔNG load file nào.
    """
    if env_file is not None and not os.path.exists(env_file):
        raise FileNotFoundError(f".env file không tồn tại: {env_file}")
    # Re-instantiate các sub-config với env_file mới (cache key theo env_file).
    return _build_settings(env_file)


def _build_settings(env_file: str | None) -> Settings:
    s = Settings()
    # Re-build từng sub-config với env_file (BaseSettings hỗ trợ truyền vào).
    s.neo4j = Neo4jConfig(_env_file=env_file)
    s.opensearch = OpenSearchConfig(_env_file=env_file)
    s.llm = LLMConfig(_env_file=env_file)
    s.nvd = NVDConfig(_env_file=env_file)
    s.test = TestConfig(_env_file=env_file)
    return s