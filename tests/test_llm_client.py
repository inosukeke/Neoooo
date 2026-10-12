"""Unit test cho llm_client.py: config env + gọi LLM qua gateway OpenAI-compatible.

Không gọi API thật — mock client/response bằng unittest.mock.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from llm_client import ConfigError, chat, check_model, load_llm_config, make_client

# --- load_llm_config: thiếu từng biến ---


def _set_all_env(monkeypatch, **overrides):
    env = {
        "OPENAI_API_KEY": "key-123",
        "OPENAI_BASE_URL": "https://gateway.example.com/v1",
        "TEXT2CYPHER_MODEL": "some-model",
    }
    env.update(overrides)
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_load_llm_config_ok(monkeypatch):
    _set_all_env(monkeypatch)
    cfg = load_llm_config()
    assert cfg.api_key == "key-123"
    assert cfg.base_url == "https://gateway.example.com/v1"
    assert cfg.model == "some-model"


def test_load_llm_config_missing_api_key(monkeypatch):
    _set_all_env(monkeypatch, OPENAI_API_KEY=None)
    with pytest.raises(ConfigError) as exc_info:
        load_llm_config()
    assert "OPENAI_API_KEY" in str(exc_info.value)


def test_load_llm_config_missing_base_url(monkeypatch):
    _set_all_env(monkeypatch, OPENAI_BASE_URL=None)
    with pytest.raises(ConfigError) as exc_info:
        load_llm_config()
    assert "OPENAI_BASE_URL" in str(exc_info.value)


def test_load_llm_config_missing_model(monkeypatch):
    _set_all_env(monkeypatch, TEXT2CYPHER_MODEL=None)
    with pytest.raises(ConfigError) as exc_info:
        load_llm_config()
    assert "TEXT2CYPHER_MODEL" in str(exc_info.value)


# --- make_client: base_url truyền tường minh ---


def test_make_client_passes_base_url_explicitly(monkeypatch):
    from llm_client import LLMConfig

    cfg = LLMConfig(
        api_key="key-123", base_url="https://gateway.example.com/v1", model="m"
    )
    client = make_client(cfg)
    # client.base_url là httpx.URL (openai SDK) — so sánh dạng str, bỏ dấu "/" cuối
    assert str(client.base_url).rstrip("/") == cfg.base_url.rstrip("/")


# --- chat: luôn gửi temperature=0 ---


def test_chat_sends_temperature_zero():
    client = MagicMock()
    response = MagicMock()
    response.choices[0].message.content = "RETURN 1"
    client.chat.completions.create.return_value = response

    result = chat(client, "some-model", [{"role": "user", "content": "hi"}])

    assert result == "RETURN 1"
    _, kwargs = client.chat.completions.create.call_args
    assert kwargs["temperature"] == 0
    assert kwargs["model"] == "some-model"


# --- check_model ---


def test_check_model_found():
    client = MagicMock()
    client.models.list.return_value.data = [
        MagicMock(id="some-model"),
        MagicMock(id="other"),
    ]
    ok, reason = check_model(client, "some-model")
    assert ok is True
    assert reason == ""


def test_check_model_not_found():
    client = MagicMock()
    client.models.list.return_value.data = [MagicMock(id="other")]
    ok, reason = check_model(client, "some-model")
    assert ok is False
    assert "some-model" in reason


def test_check_model_list_not_supported():
    client = MagicMock()
    client.models.list.side_effect = RuntimeError("endpoint not supported")
    ok, reason = check_model(client, "some-model")
    assert ok is False
    assert "endpoint not supported" in reason


# --- không hardcode tên model, không dùng OPENAI_API_BASE ---


def test_no_hardcoded_model_name_or_legacy_env_var():
    source = (
        Path(__file__)
        .parent.parent.joinpath("src", "llm", "text2cypher", "llm_client.py")
        .read_text(encoding="utf-8")
    )
    assert '"gpt-' not in source
    assert '"o1' not in source
    assert '"claude' not in source
    assert "OPENAI_API_BASE" not in source
