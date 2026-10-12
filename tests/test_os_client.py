"""Unit test cho os_client.py: mapping đúng kiểu text/keyword/date.

Test integration (OpenSearch thật) gắn @pytest.mark.integration, bị skip
bởi pytest.ini addopts (-m "not integration") khi không có OpenSearch chạy.
"""

import pytest
from os_client import ALERTS_INDEX, ALERTS_MAPPING, ensure_index, make_client


def test_computer_is_text_with_keyword_subfield():
    computer = ALERTS_MAPPING["mappings"]["properties"]["computer"]
    assert computer["type"] == "text"
    assert computer["fields"]["keyword"]["type"] == "keyword"
    assert computer["fields"]["keyword"]["ignore_above"] == 256


def test_rule_and_message_are_text_with_keyword_subfield():
    for field in ("rule", "message"):
        prop = ALERTS_MAPPING["mappings"]["properties"][field]
        assert prop["type"] == "text"
        assert prop["fields"]["keyword"]["type"] == "keyword"


def test_asset_canonical_id_is_keyword():
    prop = ALERTS_MAPPING["mappings"]["properties"]["asset_canonical_id"]
    assert prop["type"] == "keyword"


def test_time_is_date():
    prop = ALERTS_MAPPING["mappings"]["properties"]["time"]
    assert prop["type"] == "date"


def test_no_http_auth_in_make_client(monkeypatch):
    """make_client không dùng http_auth (security plugin tắt)."""
    captured = {}

    class FakeOpenSearch:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("os_client.OpenSearch", FakeOpenSearch)
    make_client()
    assert "http_auth" not in captured
    assert captured["use_ssl"] is False
    assert captured["verify_certs"] is False
    assert captured["hosts"] == [{"host": "localhost", "port": 9200}]


def test_make_client_reads_env(monkeypatch):
    captured = {}

    class FakeOpenSearch:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("os_client.OpenSearch", FakeOpenSearch)
    monkeypatch.setenv("OPENSEARCH_HOST", "myhost")
    monkeypatch.setenv("OPENSEARCH_PORT", "9999")
    make_client()
    assert captured["hosts"] == [{"host": "myhost", "port": 9999}]


@pytest.mark.integration
def test_ensure_index_creates_real_index(os_client):
    ensure_index(os_client)
    assert os_client.indices.exists(index=ALERTS_INDEX)
