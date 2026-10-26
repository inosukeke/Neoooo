"""Integration test cho src/search/join_neo4j.py: nối tay OpenSearch <-> Neo4j
qua asset_canonical_id (cả hai đang chạy thật, xem opensearch.md).

Gắn @pytest.mark.integration (cần OpenSearch + Neo4j), bị skip bởi
pytest.ini addopts (-m "not integration") nếu không thêm -m integration.
"""

import pytest
from join_neo4j import top_assets_with_kev

BURST_ASSET_ID = "ast-004"  # crosswalk["log:dc-01"] (prefix mới ast-*), khớp T013 (search_alerts)


@pytest.mark.integration
def test_top_assets_with_kev_burst_asset_has_dc01_kev_cves(os_client, neo4j_driver):
    rows = top_assets_with_kev(os_client, neo4j_driver)
    assert len(rows) > 0

    top = rows[0]
    print(f"top row: {top}")
    assert top["asset_canonical_id"] == BURST_ASSET_ID
    assert top["hostname"] == "dc-01"
    assert "CVE-2017-0144" in top["kev_cves"]
    assert "CVE-2020-1472" in top["kev_cves"]


@pytest.mark.integration
def test_top_assets_with_kev_order_matches_doc_count_desc(os_client, neo4j_driver):
    rows = top_assets_with_kev(os_client, neo4j_driver)
    doc_counts = [r["doc_count"] for r in rows]
    assert doc_counts == sorted(doc_counts, reverse=True)


@pytest.mark.integration
def test_top_assets_with_kev_rows_have_hostname_and_kev_cves_fields(
    os_client, neo4j_driver
):
    rows = top_assets_with_kev(os_client, neo4j_driver)
    for r in rows:
        assert set(r.keys()) == {
            "asset_canonical_id",
            "doc_count",
            "hostname",
            "kev_cves",
        }
        assert isinstance(r["kev_cves"], list)
