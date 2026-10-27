"""Query bool DSL demo trên index `security-alerts` (OpenSearch thật).

4 kiểu query theo `.claude/rules/opensearch.md`: terms aggregation, date
histogram, full-text match, term text-vs-keyword. Mọi body là dict literal
(không nối string vào Cypher/DSL) — xem `security.md`.
"""

from secgraph.search.os_client import ALERTS_INDEX, make_client


def top_failed_logon_by_asset(client, size: int = 10) -> list[dict]:
    """terms aggregation trên asset_canonical_id, filter bool: event_id=4625.

    Trả list [{"asset_canonical_id": bucket_key, "doc_count": n}, ...] giữ
    nguyên thứ tự ES trả về (terms agg mặc định đã sort desc theo count).
    """
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"event_id": 4625}}]}},
        "aggs": {"by_asset": {"terms": {"field": "asset_canonical_id", "size": size}}},
    }
    resp = client.search(index=ALERTS_INDEX, body=body)
    buckets = resp["aggregations"]["by_asset"]["buckets"]
    return [
        {"asset_canonical_id": b["key"], "doc_count": b["doc_count"]} for b in buckets
    ]


def daily_histogram(client, event_id: int | None = None) -> list[dict]:
    """date_histogram theo ngày (calendar_interval='day') trên field 'time'.

    Nếu event_id truyền vào, filter thêm term event_id. Trả
    list [{"date": key_as_string, "doc_count": n}, ...].
    """
    query: dict = {"bool": {"filter": []}}
    if event_id is not None:
        query["bool"]["filter"].append({"term": {"event_id": event_id}})

    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "by_day": {"date_histogram": {"field": "time", "calendar_interval": "day"}}
        },
    }
    resp = client.search(index=ALERTS_INDEX, body=body)
    buckets = resp["aggregations"]["by_day"]["buckets"]
    return [{"date": b["key_as_string"], "doc_count": b["doc_count"]} for b in buckets]


def search_message(client, text: str) -> dict:
    """match query trên field 'message' (full-text).

    Trả {"total": n, "hits": [...]}.
    """
    body = {"query": {"bool": {"must": [{"match": {"message": text}}]}}}
    resp = client.search(index=ALERTS_INDEX, body=body)
    return {
        "total": resp["hits"]["total"]["value"],
        "hits": [h["_source"] for h in resp["hits"]["hits"]],
    }


def query_alerts(
    client,
    *,
    text: str | None = None,
    asset_canonical_id: str | None = None,
    rule: str | None = None,
    success: bool | None = None,
    start: str | None = None,
    end: str | None = None,
    size: int = 20,
    from_: int = 0,
    facet_size: int = 10,
) -> dict:
    """Tìm kiếm + lọc alert cho UI (thanh search + facet + histogram + bảng).

    `text`: full-text trên field `message` (analyzed). `asset_canonical_id`/`rule`:
    exact match (`rule` dùng subfield `rule.keyword` vì field gốc là text).
    `success`: lọc đúng/sai. `start`/`end`: range trên field `time` (ISO 8601,
    cùng định dạng index_alerts ghi vào — field type `date` nên OpenSearch parse
    thật, không so sánh chuỗi). Không có filter nào -> `match_all`.

    Facet (`asset`/`rule` terms agg) + `histogram` (date_histogram theo ngày) tính
    trên CÙNG query đã lọc (không phải toàn bộ index) — phản ánh đúng phạm vi đang
    xem, không phải thống kê toàn cục.

    Trả {"total": n, "hits": [...], "facets": {"asset": [...], "rule": [...]},
    "histogram": [...]}."""
    must: list[dict] = []
    filters: list[dict] = []
    if text:
        must.append({"match": {"message": text}})
    if asset_canonical_id:
        filters.append({"term": {"asset_canonical_id": asset_canonical_id}})
    if rule:
        filters.append({"term": {"rule.keyword": rule}})
    if success is not None:
        filters.append({"term": {"success": success}})
    if start or end:
        range_bounds: dict[str, str] = {}
        if start:
            range_bounds["gte"] = start
        if end:
            range_bounds["lte"] = end
        filters.append({"range": {"time": range_bounds}})

    bool_query: dict = {}
    if must:
        bool_query["must"] = must
    if filters:
        bool_query["filter"] = filters
    query = {"bool": bool_query} if bool_query else {"match_all": {}}

    body = {
        "size": size,
        "from": from_,
        "query": query,
        "sort": [{"time": {"order": "desc"}}],
        "aggs": {
            "by_asset": {
                "terms": {"field": "asset_canonical_id", "size": facet_size}
            },
            "by_rule": {"terms": {"field": "rule.keyword", "size": facet_size}},
            "by_success": {"terms": {"field": "success"}},
            "by_day": {
                "date_histogram": {"field": "time", "calendar_interval": "day"}
            },
        },
    }
    resp = client.search(index=ALERTS_INDEX, body=body)
    aggs = resp["aggregations"]
    return {
        "total": resp["hits"]["total"]["value"],
        "hits": [h["_source"] for h in resp["hits"]["hits"]],
        "facets": {
            "asset": [
                {"key": b["key"], "doc_count": b["doc_count"]}
                for b in aggs["by_asset"]["buckets"]
            ],
            "rule": [
                {"key": b["key"], "doc_count": b["doc_count"]}
                for b in aggs["by_rule"]["buckets"]
            ],
            # terms agg trên field boolean -> key_as_string "true"/"false" (key số 1/0).
            "success": [
                {"key": b["key_as_string"], "doc_count": b["doc_count"]}
                for b in aggs["by_success"]["buckets"]
            ],
        },
        "histogram": [
            {"date": b["key_as_string"], "doc_count": b["doc_count"]}
            for b in aggs["by_day"]["buckets"]
        ],
    }


def term_vs_keyword_demo(client, computer_value: str) -> dict:
    """Minh họa rule opensearch.md: term trên field text (computer) vs computer.keyword.

    Trả {"text_field_hits": n1, "keyword_field_hits": n2} để thấy rõ khác biệt
    (text field đã bị analyzer tokenize nên term match chính xác thường ra 0
    hoặc khác, keyword field match exact).
    """
    text_body = {"query": {"term": {"computer": computer_value}}}
    keyword_body = {"query": {"term": {"computer.keyword": computer_value}}}

    text_resp = client.search(index=ALERTS_INDEX, body=text_body)
    keyword_resp = client.search(index=ALERTS_INDEX, body=keyword_body)

    return {
        "text_field_hits": text_resp["hits"]["total"]["value"],
        "keyword_field_hits": keyword_resp["hits"]["total"]["value"],
    }


if __name__ == "__main__":
    client = make_client()
    print(top_failed_logon_by_asset(client))
    print(daily_histogram(client))
    print(search_message(client, "failed"))
