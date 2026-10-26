"""UI Streamlit demo hỏi-đáp đồ thị tri thức an ninh (Text2Cypher + GraphRAG).

Chạy:  streamlit run src/ui/app.py
Yêu cầu: Neo4j đang chạy + đã nạp pipeline (xem README), env LLM trong `.env`
(OPENAI_API_KEY/OPENAI_BASE_URL/TEXT2CYPHER_MODEL/EMBEDDING_MODEL; tùy chọn
LLM_MODEL_CHAIN cho fallback theo giá). UI gọi LLM/Neo4j THẬT khi bấm "Hỏi".
"""

import contextlib
import itertools
import os
import sys
from pathlib import Path

import streamlit as st

# --- sys.path cho sibling imports (thay PYTHONPATH khi chạy streamlit run) ---
ROOT = Path(__file__).resolve().parents[2]
for _p in (
    "src/llm/text2cypher",
    "src/llm/graphrag",
    "src/graph",
    "src/search",
):
    sys.path.insert(0, str(ROOT / _p))

# Nạp .env nếu có python-dotenv (không bắt buộc — env có thể set sẵn trong shell).
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


@st.cache_resource
def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=_NEO4J_AUTH)
    driver.verify_connectivity()
    return driver


@st.cache_resource
def get_chat():
    cfg = llm_client.load_llm_config()
    return llm_client.make_client(cfg), llm_client.model_chain()


@st.cache_resource
def get_embed():
    cfg = embeddings.load_embedding_config()
    return embeddings.make_client(cfg), cfg.model


@st.cache_data(show_spinner=False)
def get_schema_text():
    return fetch_schema(get_driver())


def _chat_with_usage(messages):
    client, chain = get_chat()
    text, usage, _ = llm_client.chat_fallback(client, chain, messages)
    return text, usage


def run_text2cypher(question: str):
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
        model=chain[0],
        chat_with_usage=_chat_with_usage,
    )


def run_graphrag(question: str):
    driver = get_driver()
    emb_client, emb_model = get_embed()
    _, chain = get_chat()

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
        return [dict(r) for r in records]

    def expand(ids):
        records, _, _ = driver.execute_query(
            graphrag_demo.EXPAND_QUERY, ids=ids, database_="neo4j"
        )
        return [dict(r) for r in records]

    return graphrag_demo.answer_question(
        question,
        embed=embed,
        vector_search=vector_search,
        expand=expand,
        generate=lambda m: _chat_with_usage(m)[0],
        generate_with_usage=_chat_with_usage,
        model=chain[0],
    )


# --------------------------- UI ---------------------------
st.set_page_config(page_title="Đồ thị tri thức an ninh — Demo", page_icon="🛡️")
st.title("🛡️ Đồ thị tri thức an ninh — hỏi đáp tiếng Việt")
st.caption(
    "Demo lab (dữ liệu mô phỏng). Text2Cypher + GraphRAG tự viết trên Neo4j + GDS. "
    "LLM dùng fallback chain theo giá."
)

with st.sidebar:
    st.header("Cấu hình")
    pipeline = st.radio("Pipeline", ["Text2Cypher", "GraphRAG"])
    st.markdown(f"**Neo4j:** `{NEO4J_URI}`")
    st.markdown(f"**LLM chain:** `{', '.join(llm_client.model_chain()) or '(chưa cấu hình)'}`")
    st.caption("Text2Cypher: câu hỏi có cấu trúc. GraphRAG: câu hỏi mô tả/ngữ nghĩa.")

examples = {
    "Text2Cypher": "Máy nào chạy dịch vụ có lỗ hổng nằm trong KEV?",
    "GraphRAG": "Lỗ hổng SMB nguy hiểm nhất trên domain controller là gì?",
}
question = st.text_input("Câu hỏi", value=examples[pipeline])

if st.button("Hỏi", type="primary") and question.strip():
    with st.spinner(f"Đang chạy {pipeline}…"):
        try:
            if pipeline == "Text2Cypher":
                res = run_text2cypher(question)
                st.subheader("Trả lời")
                st.write(res.answer)
                if res.cypher:
                    st.subheader("Cypher sinh ra")
                    st.code(res.cypher, language="cypher")
                if res.rows:
                    st.subheader(f"Kết quả ({len(res.rows)} dòng)")
                    st.dataframe(res.rows)
                st.caption(
                    f"status={res.status} · {res.latency_ms} ms · "
                    f"{res.prompt_tokens + res.completion_tokens} token · model {res.model}"
                )
            else:
                res = run_graphrag(question)
                st.subheader("Trả lời")
                st.write(res.answer)
                if res.context:
                    with st.expander(f"Ngữ cảnh truy hồi ({len(res.seed_ids)} seed)"):
                        st.code(res.context)
                st.caption(
                    f"{res.latency_ms} ms · "
                    f"{res.prompt_tokens + res.completion_tokens} token · model {res.model}"
                )
        except Exception as exc:  # noqa: BLE001 - lỗi service/LLM hiển thị trong UI
            st.error(f"Lỗi: {type(exc).__name__}: {exc}")
            st.info(
                "Kiểm tra: Neo4j đang chạy + đã nạp pipeline, env LLM trong `.env`, "
                "và (GraphRAG) đã tạo vector index: "
                "`python src/llm/graphrag/graphrag_demo.py --create-index`."
            )
