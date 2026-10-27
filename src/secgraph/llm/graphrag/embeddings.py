"""Client embedding qua gateway OpenAI-compatible (SDK `openai`, không lib local).

Tên model đọc từ `EMBEDDING_MODEL`, không hardcode (giống `TEXT2CYPHER_MODEL`
ở text2cypher). Tái dùng `OPENAI_API_KEY`/`OPENAI_BASE_URL`.
"""

import os
from dataclasses import dataclass

from openai import OpenAI


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmbeddingConfig:
    api_key: str
    base_url: str
    model: str


def load_embedding_config() -> EmbeddingConfig:
    """Đọc OPENAI_API_KEY, OPENAI_BASE_URL, EMBEDDING_MODEL từ env. Thiếu biến
    nào raise ConfigError nêu đúng tên biến đó."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ConfigError(
            "Thiếu biến môi trường OPENAI_API_KEY. "
            "Set bằng: export OPENAI_API_KEY=<api_key_cua_ban>"
        )
    base_url = os.environ.get("OPENAI_BASE_URL")
    if not base_url:
        raise ConfigError(
            "Thiếu biến môi trường OPENAI_BASE_URL. "
            "Set bằng: export OPENAI_BASE_URL=<url_gateway>"
        )
    model = os.environ.get("EMBEDDING_MODEL")
    if not model:
        raise ConfigError(
            "Thiếu biến môi trường EMBEDDING_MODEL. "
            "Set bằng: export EMBEDDING_MODEL=<ten_model_embedding>"
        )
    return EmbeddingConfig(api_key=api_key, base_url=base_url, model=model)


def make_client(cfg: EmbeddingConfig) -> OpenAI:
    return OpenAI(api_key=cfg.api_key, base_url=cfg.base_url)


def embed_texts(client: OpenAI, model: str, texts: list[str]) -> list[list[float]]:
    """Embed một lô text, giữ nguyên thứ tự đầu vào."""
    vectors, _ = embed_texts_with_usage(client, model, texts)
    return vectors


def embed_texts_with_usage(
    client: OpenAI, model: str, texts: list[str]
) -> tuple[list[list[float]], int]:
    """Như `embed_texts` nhưng trả thêm tổng token embedding (0 nếu gateway không
    trả usage) — dùng để tính chi phí embedding."""
    response = client.embeddings.create(model=model, input=texts)
    ordered = sorted(response.data, key=lambda d: d.index)
    vectors = [list(d.embedding) for d in ordered]
    tokens = 0
    usage = getattr(response, "usage", None)
    if usage is not None:
        tokens = getattr(usage, "prompt_tokens", 0) or getattr(
            usage, "total_tokens", 0
        ) or 0
    return vectors, tokens
