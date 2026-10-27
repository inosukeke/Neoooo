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
):
    sys.path.insert(0, str(ROOT / _p))

with contextlib.suppress(Exception):
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")

import embeddings
import graphrag_demo
import llm_client
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
