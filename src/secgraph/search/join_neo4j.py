"""Nối tay OpenSearch <-> Neo4j qua asset_canonical_id (rule opensearch.md:
"Neo4j không có join tự động với OpenSearch — nối tay bằng asset_canonical_id").

Lấy top asset theo failed logon (OpenSearch, top_failed_logon_by_asset) rồi
bổ sung hostname + CVE KEV của asset đó (Neo4j, (Asset)-[:RUNS]->(Service)
-[:HAS_VULN]->(Vulnerability {kev: true})). Cypher luôn parameterized ($ids),
không nối chuỗi (security.md).
"""

from secgraph.search.search_alerts import (
    top_failed_logon_by_asset,  # tái dùng, không viết lại aggregation
)

KEV_BY_ASSET_QUERY = """MATCH (a:Asset) WHERE a.canonical_id IN $ids
OPTIONAL MATCH (a)-[:RUNS]->(:Service)-[:HAS_VULN]->(v:Vulnerability {kev: true})
RETURN a.canonical_id AS canonical_id, a.hostname AS hostname,
       collect(DISTINCT v.cve) AS kev_cves"""


def top_assets_with_kev(os_client, neo4j_driver, size: int = 10) -> list[dict]:
    """Ghép top asset bị failed logon (OpenSearch) với hostname + CVE KEV (Neo4j).

    Giữ đúng thứ tự từ top_failed_logon_by_asset (đã sort doc_count giảm dần).
    Trả list [{"asset_canonical_id":..., "doc_count":..., "hostname":...,
    "kev_cves": [...]}]. Asset không có hostname/CVE KEV trong Neo4j vẫn giữ
    dòng (hostname=None, kev_cves=[]).
    """
    buckets = top_failed_logon_by_asset(os_client, size)
    ids = [b["asset_canonical_id"] for b in buckets]

    neo4j_by_id: dict[str, dict] = {}
    if ids:
        with neo4j_driver.session() as session:
            result = session.run(KEV_BY_ASSET_QUERY, ids=ids)
            for record in result:
                neo4j_by_id[record["canonical_id"]] = {
                    "hostname": record["hostname"],
                    "kev_cves": record["kev_cves"],
                }

    rows = []
    for b in buckets:
        info = neo4j_by_id.get(
            b["asset_canonical_id"], {"hostname": None, "kev_cves": []}
        )
        rows.append(
            {
                "asset_canonical_id": b["asset_canonical_id"],
                "doc_count": b["doc_count"],
                "hostname": info["hostname"],
                "kev_cves": info["kev_cves"],
            }
        )
    return rows


if __name__ == "__main__":
    import os

    from neo4j import GraphDatabase

    from secgraph.search.os_client import make_client

    os_c = make_client()
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    driver = GraphDatabase.driver(uri, auth=None)
    for row in top_assets_with_kev(os_c, driver):
        print(row)
