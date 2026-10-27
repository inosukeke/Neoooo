"""Logic dùng chung cho mọi UI (Streamlit `src/ui/app.py` và FastAPI `src/api/`)
gọi Text2Cypher/GraphRAG thật trên Neo4j + LLM gateway.

Framework-agnostic: không import Streamlit/FastAPI ở đây — chỉ wiring
driver/client + 2 hàm `run_text2cypher`/`run_graphrag` + `get_health()`.
Yêu cầu Neo4j đang chạy + đã nạp pipeline, env LLM trong `.env`/shell
(OPENAI_API_KEY/OPENAI_BASE_URL/TEXT2CYPHER_MODEL/EMBEDDING_MODEL; tùy chọn
LLM_MODEL_CHAIN).
"""

import contextlib
import itertools
import os
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

# --- sys.path cho sibling imports (như src/ui/app.py) ------------------------
ROOT = Path(__file__).resolve().parents[2]
for _p in (
    "src/llm/text2cypher",
    "src/llm/graphrag",
    "src/graph",
    "src/search",
    "src/analysis/risk",
    "src/analysis/attack_path",
):
    sys.path.insert(0, str(ROOT / _p))

with contextlib.suppress(Exception):
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")

import attack_path
import embeddings
import graphrag_demo
import llm_client
import os_client
import risk_scoring
import search_alerts
import text2cypher as t2c
from neo4j import GraphDatabase, Query
from schema_text import fetch_schema

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
_NEO4J_PW = os.environ.get("NEO4J_PASSWORD")
_NEO4J_AUTH = (os.environ.get("NEO4J_USER", "neo4j"), _NEO4J_PW) if _NEO4J_PW else None


@lru_cache(maxsize=1)
def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=_NEO4J_AUTH)
    driver.verify_connectivity()
    return driver


@lru_cache(maxsize=1)
def get_chat():
    cfg = llm_client.load_llm_config()
    return llm_client.make_client(cfg), llm_client.model_chain()


@lru_cache(maxsize=1)
def get_embed():
    cfg = embeddings.load_embedding_config()
    return embeddings.make_client(cfg), cfg.model


@lru_cache(maxsize=1)
def get_schema_text():
    return fetch_schema(get_driver())


@lru_cache(maxsize=1)
def get_search_client():
    return os_client.make_client()


def _chat_with_usage(messages):
    client, chain = get_chat()
    text, usage, _ = llm_client.chat_fallback(client, chain, messages)
    return text, usage


def run_text2cypher(question: str) -> t2c.Text2CypherResult:
    driver = get_driver()
    schema = get_schema_text()

    def explain(cypher):
        with driver.session(default_access_mode="READ") as s:
            s.run(Query("EXPLAIN " + cypher, timeout=t2c.QUERY_TIMEOUT_SECONDS))

    def execute(cypher):
        with driver.session(default_access_mode="READ") as s:
            result = s.run(Query(cypher, timeout=t2c.QUERY_TIMEOUT_SECONDS))
            return [dict(r) for r in itertools.islice(result, t2c.MAX_ROWS)]

    _, chain = get_chat()
    return t2c.answer_question(
        question,
        schema=schema,
        few_shots=t2c.load_few_shots(),
        generate=lambda m: _chat_with_usage(m)[0],
        interpret=lambda m: _chat_with_usage(m)[0],
        explain=explain,
        execute=execute,
        model=chain[0] if chain else "",
        chat_with_usage=_chat_with_usage,
    )


def run_graphrag(question: str) -> tuple[graphrag_demo.GraphRAGResult, dict]:
    """Như `graphrag_demo.answer_question`, nhưng trả thêm `seed_scores`
    (`{cve: cosine_score}`) lấy từ kết quả `vector_search` thật — field này
    KHÔNG có trong `GraphRAGResult` gốc (chỉ có `seed_ids`, không có score)."""
    driver = get_driver()
    emb_client, emb_model = get_embed()
    _, chain = get_chat()
    captured_seeds: list[dict] = []

    def embed(text):
        return embeddings.embed_texts(emb_client, emb_model, [text])[0]

    def vector_search(embedding):
        records, _, _ = driver.execute_query(
            graphrag_demo.VECTOR_SEARCH_QUERY,
            top_k=graphrag_demo.DEFAULT_TOP_K,
            embedding=embedding,
            min_score=0.0,
            database_="neo4j",
        )
        rows = [dict(r) for r in records]
        captured_seeds.extend(rows)
        return rows

    def expand(ids):
        records, _, _ = driver.execute_query(
            graphrag_demo.EXPAND_QUERY, ids=ids, database_="neo4j"
        )
        return [dict(r) for r in records]

    result = graphrag_demo.answer_question(
        question,
        embed=embed,
        vector_search=vector_search,
        expand=expand,
        generate=lambda m: _chat_with_usage(m)[0],
        generate_with_usage=_chat_with_usage,
        model=chain[0] if chain else "",
    )
    seed_scores = {
        r["id"]: r["score"]
        for r in captured_seeds
        if r.get("id") is not None and r.get("score") is not None
    }
    return result, seed_scores


def get_health() -> dict:
    """Trạng thái hạ tầng thật (Neo4j + vector index + model chain + số node)
    cho sidebar/topbar của UI — không có số liệu bịa."""
    checked_at = datetime.now(UTC).isoformat()
    neo4j_connected = True
    neo4j_error: str | None = None
    try:
        get_driver().verify_connectivity()
    except Exception as exc:  # noqa: BLE001 - Neo4j có thể chưa chạy, UI cần hiển thị lỗi này
        neo4j_connected = False
        neo4j_error = str(exc)

    vector_state = "unknown"
    vector_error: str | None = None
    asset_count: int | None = None
    user_count: int | None = None

    if neo4j_connected:
        driver = get_driver()
        try:
            with driver.session(default_access_mode="READ") as s:
                rec = s.run(
                    "SHOW INDEXES YIELD name, state WHERE name = $name RETURN state",
                    name=graphrag_demo.VECTOR_INDEX_NAME,
                ).single()
                vector_state = rec["state"] if rec else "MISSING"
        except Exception as exc:  # noqa: BLE001 - hiển thị lỗi thay vì crash health check
            vector_error = str(exc)
        try:
            with driver.session(default_access_mode="READ") as s:
                rec = s.run(
                    "MATCH (a:Asset) WITH count(a) AS assets "
                    "MATCH (u:User) RETURN assets, count(u) AS users"
                ).single()
                if rec:
                    asset_count, user_count = rec["assets"], rec["users"]
        except Exception:  # noqa: BLE001 - đếm thất bại không nên chặn phần health còn lại
            asset_count = user_count = None

    return {
        "neo4j": {"connected": neo4j_connected, "uri": NEO4J_URI, "error": neo4j_error},
        "vector_index": {
            "name": graphrag_demo.VECTOR_INDEX_NAME,
            "state": vector_state,
            "error": vector_error,
        },
        "model_chain": llm_client.model_chain(),
        "graph_summary": {"asset_count": asset_count, "user_count": user_count},
        "read_only": True,
        "checked_at": checked_at,
    }


# Đếm theo nhãn thật trong Schema v2 (xem docs/giai-doan-01-graph-foundations/
# mo-hinh-hoa-du-lieu.md) — dùng cho trang Tổng quan. Không đụng attack_path.py/
# risk_scoring.py (chưa có API) nên không có risk score/đường tấn công ở đây.
_OVERVIEW_COUNT_QUERY = (
    "MATCH (a:Asset) WITH count(a) AS asset "
    "MATCH (u:User) WITH asset, count(u) AS usr "
    "MATCH (v:Vulnerability) WITH asset, usr, count(v) AS vuln, "
    "  sum(CASE WHEN v.kev THEN 1 ELSE 0 END) AS vuln_kev "
    "MATCH (sv:Service) WITH asset, usr, vuln, vuln_kev, count(sv) AS service "
    "MATCH (ac:Account) WITH asset, usr, vuln, vuln_kev, service, count(ac) AS account "
    "MATCH (g:Group) WITH asset, usr, vuln, vuln_kev, service, account, count(g) AS grp "
    "MATCH (al:Alert) "
    "RETURN asset, usr, vuln, vuln_kev, service, account, grp, count(al) AS alert"
)


def get_overview() -> dict:
    """Số liệu KPI thật cho trang Tổng quan — tái dùng `get_health()` cho phần
    hạ tầng, chỉ thêm đếm node theo nhãn (không có số bịa)."""
    health = get_health()
    counts = {
        "asset_count": None,
        "user_count": None,
        "vulnerability_count": None,
        "vulnerability_kev_count": None,
        "service_count": None,
        "account_count": None,
        "group_count": None,
        "alert_count": None,
    }
    if health["neo4j"]["connected"]:
        try:
            with get_driver().session(default_access_mode="READ") as s:
                rec = s.run(_OVERVIEW_COUNT_QUERY).single()
                if rec:
                    counts = {
                        "asset_count": rec["asset"],
                        "user_count": rec["usr"],
                        "vulnerability_count": rec["vuln"],
                        "vulnerability_kev_count": rec["vuln_kev"],
                        "service_count": rec["service"],
                        "account_count": rec["account"],
                        "group_count": rec["grp"],
                        "alert_count": rec["alert"],
                    }
        except Exception:  # noqa: BLE001 - đếm thất bại không nên chặn phần còn lại
            counts = dict.fromkeys(counts)
    return {**health, "counts": counts}


# Ngưỡng demo tự chọn để đếm KPI "rủi ro cao" — không phải chuẩn ngành, chỉ để
# phân nhóm trực quan trên UI (risk_score trong 0..1, xem risk_scoring.py).
HIGH_RISK_THRESHOLD = 0.5


def get_risk_ranking() -> dict:
    """Xếp hạng risk thật (Giai đoạn 04, `risk_scoring.run_risk_scoring`) cho trang
    Risk & Patch. Luôn chạy dry-run (`write=False, assign_context=False`, đúng khớp
    CLI `--dry-run`) — GET không được phép biến đổi đồ thị khi tải trang.

    `patch_priority` = max(PageRank chuẩn hoá, asset_criticality/5). PageRank tính
    thật qua GDS (`attack_path.pagerank`, chiếu topology tạm thời tự drop) rồi
    truyền vào runner — `pagerank_wired=True`. Nếu GDS lỗi thì fallback về {} (khi
    đó patch_priority chỉ còn asset_criticality/5) và `pagerank_wired=False`."""
    driver = get_driver()
    try:
        pr = attack_path.pagerank(driver)
    except Exception:  # noqa: BLE001 - GDS lỗi không nên chặn trang Risk; fallback criticality
        pr = {}
    risks = risk_scoring.run_risk_scoring(
        driver, write=False, assign_context=False, pagerank=pr
    )
    items = [
        {
            "canonical_id": r.canonical_id,
            "hostname": r.hostname,
            "risk_score": r.risk_score,
            "cost": r.cost,
            "patch_priority": r.patch_priority,
            "drivers": r.drivers,
        }
        for r in risks
    ]
    scores = [r.risk_score for r in risks]
    return {
        "items": items,
        "summary": {
            "scored_asset_count": len(risks),
            "high_risk_count": sum(1 for s in scores if s > HIGH_RISK_THRESHOLD),
            "high_risk_threshold": HIGH_RISK_THRESHOLD,
            "avg_risk_score": (sum(scores) / len(scores)) if scores else None,
            "pagerank_wired": bool(pr),
        },
    }


def get_alerts(
    *,
    text: str | None = None,
    asset_canonical_id: str | None = None,
    rule: str | None = None,
    success: bool | None = None,
    start: str | None = None,
    end: str | None = None,
    size: int = 20,
    from_: int = 0,
) -> dict:
    """Tìm kiếm/lọc alert thật (Giai đoạn 02, index OpenSearch `security-alerts`)
    cho trang Alert & tìm kiếm log — bọc mỏng `search_alerts.query_alerts`, không
    bịa field (xem `.claude/rules/opensearch.md`)."""
    return search_alerts.query_alerts(
        get_search_client(),
        text=text,
        asset_canonical_id=asset_canonical_id,
        rule=rule,
        success=success,
        start=start,
        end=end,
        size=size,
        from_=from_,
    )


# Đọc toàn bộ Asset + CONNECTS_TO cho canvas đồ thị (UI tự vẽ, xem
# .claude/rules/graph-schema.md). CHỈ ĐỌC — không liên quan tới GDS.
_GRAPH_ASSETS_QUERY = """MATCH (a:Asset)
RETURN a.canonical_id AS canonical_id, a.hostname AS hostname,
       a.asset_criticality AS asset_criticality
ORDER BY canonical_id"""

_GRAPH_EDGES_QUERY = """MATCH (a:Asset)-[r:CONNECTS_TO]->(b:Asset)
RETURN a.canonical_id AS src, b.canonical_id AS dst, r.cost AS cost"""


def get_attack_path(*, min_criticality: int = 4) -> dict:
    """Đồ thị Asset + CONNECTS_TO + kết quả 3 thuật toán tấn công thật (Giai đoạn 04,
    `attack_path.run_attack_path`: Dijkstra theo cost, BFS reachability, betweenness
    choke point) cho trang Đồ thị & đường tấn công.

    CHỈ ĐỌC: node/edge đọc bằng session READ, `run_attack_path` chỉ gọi
    `gds.*.stream` (không `.write`/`.mutate`) trên bản chiếu GDS tạm thời tự drop
    ngay sau khi tính (xem `attack_path.drop_projections`) — không ghi gì vào
    Neo4j khi tải trang. Nếu `CONNECTS_TO.cost` thiếu/sai (risk_scoring.py chưa
    chạy), `attack_path.MissingCostError` sẽ raise ra ngoài — KHÔNG tự ý chạy
    risk_scoring để "sửa", để API layer trả lỗi rõ ràng."""
    driver = get_driver()
    with driver.session(default_access_mode="READ") as s:
        asset_rows = [r.data() for r in s.run(_GRAPH_ASSETS_QUERY)]
        edge_rows = [r.data() for r in s.run(_GRAPH_EDGES_QUERY)]

    entries = attack_path.find_entry_points(driver)
    crowns = attack_path.find_crown_jewels(driver, min_criticality=min_criticality)
    paths, chokes, freq, reachable = attack_path.run_attack_path(
        driver, min_criticality=min_criticality
    )

    entry_set, crown_set = set(entries), set(crowns)
    nodes = [
        {
            "canonical_id": a["canonical_id"],
            "hostname": a["hostname"],
            "asset_criticality": a["asset_criticality"],
            "is_entry_point": a["canonical_id"] in entry_set,
            "is_crown_jewel": a["canonical_id"] in crown_set,
        }
        for a in asset_rows
    ]
    edges = [{"src": e["src"], "dst": e["dst"], "cost": e["cost"]} for e in edge_rows]

    return {
        "nodes": nodes,
        "edges": edges,
        "entry_points": entries,
        "crown_jewels": crowns,
        "paths": [
            {
                "source": p.source,
                "target": p.target,
                "total_cost": p.total_cost,
                "hops": p.hops,
            }
            for p in paths
        ],
        "choke_points": [
            {
                "canonical_id": c.canonical_id,
                "hostname": c.hostname,
                "betweenness": c.betweenness,
            }
            for c in chokes
        ],
        "path_frequency": [{"canonical_id": cid, "count": n} for cid, n in freq],
        "reachable": sorted(reachable),
        "min_criticality": min_criticality,
    }
