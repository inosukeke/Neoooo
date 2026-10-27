"""UI Streamlit demo hỏi-đáp đồ thị tri thức an ninh (Text2Cypher + GraphRAG).

Chạy:  streamlit run src/ui/app.py
Yêu cầu: Neo4j đang chạy + đã nạp pipeline (xem README), env LLM trong `.env`
(OPENAI_API_KEY/OPENAI_BASE_URL/TEXT2CYPHER_MODEL/EMBEDDING_MODEL; tùy chọn
LLM_MODEL_CHAIN cho fallback theo giá). UI gọi LLM/Neo4j THẬT khi bấm "Hỏi".
"""

import streamlit as st

from secgraph.pipelines.service import (
    NEO4J_URI,
    llm_client,
    run_graphrag,
    run_text2cypher,
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
                res, _seed_scores = run_graphrag(question)
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
