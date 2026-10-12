"""Cấu hình + gọi LLM qua gateway OpenAI-compatible.

Không hardcode tên model (tên model gateway đổi nhanh) — đọc từ
`TEXT2CYPHER_MODEL`. Dùng `temperature=0` khi sinh Cypher (xem
`.claude/rules/text2cypher.md`).
"""

import os
from dataclasses import dataclass

from openai import OpenAI


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    base_url: str
    model: str


def load_llm_config() -> LLMConfig:
    """Đọc OPENAI_API_KEY, OPENAI_BASE_URL, TEXT2CYPHER_MODEL từ env.

    Thiếu biến nào raise ConfigError nêu đúng tên biến đó, không có default
    cho model (tên model đổi nhanh, không được đoán)."""
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

    model = os.environ.get("TEXT2CYPHER_MODEL")
    if not model:
        raise ConfigError(
            "Thiếu biến môi trường TEXT2CYPHER_MODEL. "
            "Set bằng: export TEXT2CYPHER_MODEL=<ten_model>"
        )

    return LLMConfig(api_key=api_key, base_url=base_url, model=model)


def make_client(cfg: LLMConfig) -> OpenAI:
    """Truyền base_url tường minh, không chỉ dựa vào SDK tự đọc env."""
    return OpenAI(api_key=cfg.api_key, base_url=cfg.base_url)


def chat(client: OpenAI, model: str, messages: list[dict]) -> str:
    """Gọi chat completion với temperature=0 (xác định, không ngẫu nhiên)."""
    response = client.chat.completions.create(
        model=model, messages=messages, temperature=0
    )
    return response.choices[0].message.content


def check_model(client: OpenAI, model: str) -> tuple[bool, str]:
    """Kiểm model có trong danh sách model gateway hỗ trợ không."""
    try:
        models = client.models.list()
    except Exception as exc:  # noqa: BLE001 - gateway có thể không hỗ trợ endpoint này
        return False, f"Không gọi được models.list() trên gateway: {exc}"

    available_ids = [m.id for m in models.data]
    if model in available_ids:
        return True, ""

    return (
        False,
        (
            f"Model '{model}' không khả dụng trên gateway (danh sách hiện có: "
            f"{available_ids}). Thử chạy lại với TEXT2CYPHER_MODEL khác."
        ),
    )
