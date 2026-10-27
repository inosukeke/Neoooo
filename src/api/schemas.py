"""Pydantic request/response models cho FastAPI — tách khỏi main.py cho gọn."""

from typing import Literal

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    pipeline: Literal["text2cypher", "graphrag"]
    question: str = Field(min_length=1, max_length=2000)


class Text2CypherAnswer(BaseModel):
    pipeline: Literal["text2cypher"] = "text2cypher"
    question: str
    status: Literal["ok", "rejected_write", "failed"]
    answer: str
    cypher: str | None
    rows: list[dict]
    errors: list[str]
    attempts: int
    fixes: list[str]
    latency_ms: int
    prompt_tokens: int
    completion_tokens: int
    model: str


class RetrievedSource(BaseModel):
    """Một bản ghi trong ngữ cảnh GraphRAG (`context`, JSON-lines), kèm điểm
    tương đồng thật nếu đây là một trong các seed node (`seed_scores`) —
    record mở rộng qua `EXPAND_QUERY` (không phải seed) thì `score=None`."""

    id: str
    score: float | None = None
    data: dict


class GraphRAGAnswer(BaseModel):
    pipeline: Literal["graphrag"] = "graphrag"
    question: str
    answer: str
    sources: list[RetrievedSource]
    seed_ids: list
    latency_ms: int
    prompt_tokens: int
    completion_tokens: int
    model: str


class Neo4jHealth(BaseModel):
    connected: bool
    uri: str
    error: str | None = None


class VectorIndexHealth(BaseModel):
    name: str
    state: str
    error: str | None = None


class GraphSummary(BaseModel):
    asset_count: int | None = None
    user_count: int | None = None


class HealthResponse(BaseModel):
    neo4j: Neo4jHealth
    vector_index: VectorIndexHealth
    model_chain: list[str]
    graph_summary: GraphSummary
    read_only: bool
    checked_at: str
