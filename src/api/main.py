"""FastAPI backend bọc 2 pipeline Text2Cypher/GraphRAG (xem `src/pipelines/service.py`)
cho UI web mới (`web/`). Dùng chung logic với `src/ui/app.py` (Streamlit) — không
có bộ nhớ hội thoại: mỗi `POST /ask` xử lý độc lập.

Chạy:  uvicorn main:app --reload --port 8000 --app-dir src/api
(`--app-dir` thêm `src/api` vào sys.path để import `main`/`schemas` như module
top-level — cùng kiểu sys.path phẳng mà các script khác trong repo dùng, xem
`pytest.ini`.)
Yêu cầu: Neo4j đang chạy + đã nạp pipeline, env LLM trong `.env`/shell (xem
`src/pipelines/service.py`). CORS origin đọc từ env `API_CORS_ORIGINS`
(phẩy ngăn cách, mặc định `http://localhost:3000`).
"""

import json
import os
import sys
from pathlib import Path

# `prompts` (để lấy to_jsonable) sống trong src/llm/text2cypher — thêm path
# tường minh ở đây, không dựa vào thứ tự import `service` (ruff sắp xếp lại
# import theo alphabet, không giữ thứ tự import gốc).
_SRC = Path(__file__).resolve().parents[1]
for _p in (_SRC / "pipelines", _SRC / "llm" / "text2cypher"):
    sys.path.insert(0, str(_p))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prompts import to_jsonable
from schemas import (
    AskRequest,
    GraphRAGAnswer,
    GraphSummary,
    HealthResponse,
    Neo4jHealth,
    RetrievedSource,
    Text2CypherAnswer,
    VectorIndexHealth,
)
from service import get_health, run_graphrag, run_text2cypher

app = FastAPI(title="Đồ thị tri thức an ninh — API", version="0.1.0")

_origins = [
    o.strip()
    for o in os.environ.get("API_CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _parse_graphrag_sources(
    context: str, seed_scores: dict[str, float]
) -> list[RetrievedSource]:
    """`context` là JSON-lines (một record/dòng, xem `graphrag_demo.build_context`).
    Gắn `score` thật nếu record đó là 1 trong các seed vector search."""
    sources: list[RetrievedSource] = []
    for line in context.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = record.get("id")
        sources.append(
            RetrievedSource(
                id=str(rid) if rid is not None else "",
                score=seed_scores.get(rid),
                data=record,
            )
        )
    return sources


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    data = get_health()
    return HealthResponse(
        neo4j=Neo4jHealth(**data["neo4j"]),
        vector_index=VectorIndexHealth(**data["vector_index"]),
        model_chain=data["model_chain"],
        graph_summary=GraphSummary(**data["graph_summary"]),
        read_only=data["read_only"],
        checked_at=data["checked_at"],
    )


@app.post("/ask", response_model=Text2CypherAnswer | GraphRAGAnswer)
def ask(req: AskRequest) -> Text2CypherAnswer | GraphRAGAnswer:
    try:
        if req.pipeline == "text2cypher":
            result = run_text2cypher(req.question)
            return Text2CypherAnswer(
                question=result.question,
                status=result.status,
                answer=result.answer,
                cypher=result.cypher,
                rows=to_jsonable(result.rows),
                errors=result.errors,
                attempts=result.attempts,
                fixes=result.fixes,
                latency_ms=result.latency_ms,
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                model=result.model,
            )

        result, seed_scores = run_graphrag(req.question)
        return GraphRAGAnswer(
            question=result.question,
            answer=result.answer,
            sources=_parse_graphrag_sources(result.context, seed_scores),
            seed_ids=result.seed_ids,
            latency_ms=result.latency_ms,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            model=result.model,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502, detail=f"{type(exc).__name__}: {exc}"
        ) from exc
