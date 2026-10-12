"""Integration test cho src/search/search_alerts.py: 4 query bool DSL trên
index `security-alerts` (OpenSearch thật, 1620 doc đã index sẵn bởi T006).

Toàn bộ test gắn @pytest.mark.integration (cần OpenSearch đang chạy), bị
skip bởi pytest.ini addopts (-m "not integration") nếu không thêm -m integration.
"""

import pytest
from search_alerts import (
    daily_histogram,
    search_message,
    term_vs_keyword_demo,
    top_failed_logon_by_asset,
)

BURST_ASSET_ID = "asset-014"  # crosswalk["log:dc-01"], xem index_alerts.BURST_COMPUTER


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
