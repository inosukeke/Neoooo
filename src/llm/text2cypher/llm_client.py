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


# --- Fallback nhiều model theo GIÁ thấp→cao (gateway shopaikey) ---------------
# Mặc định: rẻ nhất trước, kết ở model nhiều kênh nhất (gpt-4o-mini, 5 kênh) cho
# ổn định. Đơn giá tham chiếu (input/output $/1M): gpt-5-nano 0.06/0.48,
# gpt-4.1-nano 0.12/0.48, gpt-4o-mini 0.18/0.72. Ghi đè bằng env LLM_MODEL_CHAIN
# (danh sách phẩy ngăn cách). gpt-5-nano hiện hay trả 503 (no available channel)
# nên fallback là cần thiết — đã quan sát thật.
_RETRYABLE_MARKERS = (
    "model_not_found",
    "no available channel",
    "rate limit",
    "rate_limit",
    "overloaded",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "service unavailable",
    "access denied",
    "quota",
    "permission",
)


def model_chain() -> list[str]:
    """Danh sách model chat theo thứ tự thử (giá thấp→cao). Đọc từ env
    LLM_MODEL_CHAIN (phẩy ngăn cách); nếu không có, dùng [TEXT2CYPHER_MODEL].
    KHÔNG hardcode tên model trong code (xem test_no_hardcoded_model_name) — chain
    cụ thể đặt trong `.env`. Gợi ý cho gateway hiện tại (rẻ→đắt, model cuối nhiều
    kênh nhất nên ổn định): gpt-5-nano, gpt-4.1-nano, gpt-4o-mini."""
    raw = os.environ.get("LLM_MODEL_CHAIN", "").strip()
    if raw:
        return [m.strip() for m in raw.split(",") if m.strip()]
    single = os.environ.get("TEXT2CYPHER_MODEL", "").strip()
    return [single] if single else []


def _is_retryable(exc: Exception) -> bool:
    """Lỗi nên thử model kế tiếp: 5xx/429/timeout/model không khả dụng.
    Lỗi khác (vd 400 bad request, auth 401) KHÔNG retry — raise ngay."""
    status = getattr(exc, "status_code", None)
    # 403 = model bị từ chối/hết quota RIÊNG model đó (gateway cấp access theo từng
    # model) → thử model kế trong chain. 401 (sai key) KHÔNG retry — mọi model fail.
    if isinstance(status, int) and (status >= 500 or status in (429, 403)):
        return True
    msg = str(exc).lower()
    return any(marker in msg for marker in _RETRYABLE_MARKERS)


def chat_fallback(
    client: OpenAI,
    models: list[str],
    messages: list[dict],
    *,
    temperature: float = 0,
) -> tuple[str, dict, str]:
    """Thử lần lượt `models` (giá thấp→cao). Lỗi retryable → model kế; lỗi khác →
    raise ngay. Trả `(content, usage_dict, model_used)`. Hết model → raise lỗi cuối.

    `usage_dict` có `prompt_tokens`/`completion_tokens` (0 nếu gateway không trả)."""
    if not models:
        raise ConfigError("Danh sách model rỗng — set LLM_MODEL_CHAIN hoặc TEXT2CYPHER_MODEL.")
    last_exc: Exception | None = None
    for model in models:
        try:
            resp = client.chat.completions.create(
                model=model, messages=messages, temperature=temperature
            )
            usage = {}
            if resp.usage is not None:
                usage = {
                    "prompt_tokens": resp.usage.prompt_tokens or 0,
                    "completion_tokens": resp.usage.completion_tokens or 0,
                }
            return resp.choices[0].message.content or "", usage, model
        except Exception as exc:
            last_exc = exc
            if _is_retryable(exc):
                continue
            raise
    raise last_exc  # type: ignore[misc]


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
