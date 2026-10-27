"""Integration test cho src/search/search_alerts.py: 4 query bool DSL trên
index `security-alerts` (OpenSearch thật, 1620 doc đã index sẵn bởi T006).

Toàn bộ test gắn @pytest.mark.integration (cần OpenSearch đang chạy), bị
skip bởi pytest.ini addopts (-m "not integration") nếu không thêm -m integration.
"""

import pytest

from secgraph.search.search_alerts import (
    daily_histogram,
    query_alerts,
    search_message,
    term_vs_keyword_demo,
    top_failed_logon_by_asset,
)

BURST_ASSET_ID = "ast-004"  # crosswalk["log:dc-01"] (prefix mới ast-*), xem index_alerts.BURST_COMPUTER


class FakeOpenSearch:
    """Fake client capture body gửi đi + trả response giả lập (unit test, không
    cần OpenSearch thật) — cùng kiểu FakeOpenSearch ở tests/test_os_client.py."""

    def __init__(self, response: dict):
        self._response = response
        self.last_call: dict | None = None

    def search(self, index, body):
        self.last_call = {"index": index, "body": body}
        return self._response


_CANNED_RESPONSE = {
    "hits": {
        "total": {"value": 2},
        "hits": [
            {"_source": {"alert_id": "AL-1", "message": "failed logon"}},
            {"_source": {"alert_id": "AL-2", "message": "ok logon"}},
        ],
    },
    "aggregations": {
        "by_asset": {
            "buckets": [{"key": "ast-004", "doc_count": 5}, {"key": "ast-001", "doc_count": 3}]
        },
        "by_rule": {"buckets": [{"key": "Failed logon (4625)", "doc_count": 5}]},
        "by_success": {
            "buckets": [
                {"key_as_string": "false", "doc_count": 5},
                {"key_as_string": "true", "doc_count": 3},
            ]
        },
        "by_day": {
            "buckets": [
                {"key_as_string": "2026-10-04T00:00:00.000Z", "doc_count": 4},
                {"key_as_string": "2026-10-05T00:00:00.000Z", "doc_count": 1},
            ]
        },
    },
}


def test_query_alerts_no_filters_uses_match_all():
    client = FakeOpenSearch(_CANNED_RESPONSE)
    query_alerts(client)
    assert client.last_call["body"]["query"] == {"match_all": {}}
    assert client.last_call["body"]["sort"] == [{"time": {"order": "desc"}}]


def test_query_alerts_builds_bool_with_must_and_filters():
    client = FakeOpenSearch(_CANNED_RESPONSE)
    query_alerts(
        client,
        text="failed",
        asset_canonical_id="ast-004",
        rule="Failed logon (4625)",
        success=False,
        start="2026-10-01T00:00:00Z",
        end="2026-10-10T00:00:00Z",
    )
    body = client.last_call["body"]
    assert body["query"]["bool"]["must"] == [{"match": {"message": "failed"}}]
    assert {"term": {"asset_canonical_id": "ast-004"}} in body["query"]["bool"]["filter"]
    assert {"term": {"rule.keyword": "Failed logon (4625)"}} in body["query"]["bool"]["filter"]
    assert {"term": {"success": False}} in body["query"]["bool"]["filter"]
    assert {
        "range": {"time": {"gte": "2026-10-01T00:00:00Z", "lte": "2026-10-10T00:00:00Z"}}
    } in body["query"]["bool"]["filter"]


def test_query_alerts_parses_response_shape():
    client = FakeOpenSearch(_CANNED_RESPONSE)
    result = query_alerts(client, size=2)
    assert result["total"] == 2
    assert result["hits"] == [
        {"alert_id": "AL-1", "message": "failed logon"},
        {"alert_id": "AL-2", "message": "ok logon"},
    ]
    assert result["facets"]["asset"] == [
        {"key": "ast-004", "doc_count": 5},
        {"key": "ast-001", "doc_count": 3},
    ]
    assert result["facets"]["rule"] == [{"key": "Failed logon (4625)", "doc_count": 5}]
    assert result["facets"]["success"] == [
        {"key": "false", "doc_count": 5},
        {"key": "true", "doc_count": 3},
    ]
    assert result["histogram"] == [
        {"date": "2026-10-04T00:00:00.000Z", "doc_count": 4},
        {"date": "2026-10-05T00:00:00.000Z", "doc_count": 1},
    ]


@pytest.mark.integration
def test_top_failed_logon_by_asset_burst_first(os_client):
    buckets = top_failed_logon_by_asset(os_client)
    assert len(buckets) > 0
    top = buckets[0]
    assert top["asset_canonical_id"] == BURST_ASSET_ID
    print(f"top asset: {top}")


@pytest.mark.integration
def test_daily_histogram_14_buckets(os_client):
    buckets = daily_histogram(os_client)
    print(f"so bucket: {len(buckets)}")
    assert len(buckets) == 14
    for b in buckets:
        assert "date" in b
        assert b["doc_count"] > 0


@pytest.mark.integration
def test_daily_histogram_with_event_id_filter(os_client):
    buckets = daily_histogram(os_client, event_id=4625)
    total = sum(b["doc_count"] for b in buckets)
    print(f"tong doc event_id=4625 theo histogram: {total}")
    assert total == 470


@pytest.mark.integration
def test_search_message_failed_matches_4625_count(os_client):
    result = search_message(os_client, "failed")
    print(f"total hits 'failed': {result['total']}")
    assert result["total"] == 470
    assert len(result["hits"]) > 0


@pytest.mark.integration
def test_term_vs_keyword_demo_dc01(os_client):
    result = term_vs_keyword_demo(os_client, "dc-01")
    print(
        f"text_field_hits={result['text_field_hits']} keyword_field_hits={result['keyword_field_hits']}"
    )
    assert result["keyword_field_hits"] > 0
    assert result["text_field_hits"] != result["keyword_field_hits"]
