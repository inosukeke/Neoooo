"""Client OpenSearch local no-auth + mapping index alert.

Xem `.claude/rules/opensearch.md`: DISABLE_SECURITY_PLUGIN=true chỉ dev local,
không dùng http_auth. Mapping phân biệt field `text` (full-text) vs `keyword`
(exact match/aggregation) — `term` trên field text cho kết quả khác/rỗng.
"""

import os

from opensearchpy import OpenSearch

ALERTS_INDEX = "security-alerts"

TEXT_KW = {
    "type": "text",
    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
}

ALERTS_MAPPING = {
    "mappings": {
        "properties": {
            "alert_id": {"type": "keyword"},
            "orig_alert_id": {"type": "keyword"},
            "time": {"type": "date"},
            "event_id": {"type": "integer"},
            "success": {"type": "boolean"},
            "outcome": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "rule": TEXT_KW,
            "message": TEXT_KW,
            "computer": TEXT_KW,
            "target_user": {"type": "keyword"},
            "asset_canonical_id": {"type": "keyword"},
            "user_canonical_id": {"type": "keyword"},
            "source": {"type": "keyword"},
            "synthetic": {"type": "boolean"},
            "scenario": {"type": "keyword"},
            # S2 (D.2): các field SIEM chuẩn (parent/child analysis, lateral movement)
            "source_ip": {"type": "ip"},
            "dest_ip": {"type": "ip"},
            "source_port": {"type": "integer"},
            "dest_port": {"type": "integer"},
            "process_name": {"type": "keyword"},
            "process_path": {"type": "keyword"},
            "parent_process": TEXT_KW,
            "file_hash": {"type": "keyword"},
            "file_path": {"type": "keyword"},
        }
    }
}


def make_client() -> OpenSearch:
    """Dựng client OpenSearch local no-auth (DISABLE_SECURITY_PLUGIN=true)."""
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )


def ensure_index(
    client: OpenSearch, index: str = ALERTS_INDEX, mapping: dict = ALERTS_MAPPING
) -> None:
    """Tạo index với mapping nếu chưa tồn tại (idempotent)."""
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=mapping)
