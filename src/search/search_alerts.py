"""Query bool DSL demo trên index `security-alerts` (OpenSearch thật).

4 kiểu query theo `.claude/rules/opensearch.md`: terms aggregation, date
histogram, full-text match, term text-vs-keyword. Mọi body là dict literal
(không nối string vào Cypher/DSL) — xem `security.md`.
"""

from os_client import ALERTS_INDEX, make_client


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
