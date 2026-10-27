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


class OverviewCounts(BaseModel):
    """Đếm thật theo nhãn Schema v2 — không có risk score/đường tấn công (chưa
    có API cho attack_path.py/risk_scoring.py)."""

    asset_count: int | None = None
    user_count: int | None = None
    vulnerability_count: int | None = None
    vulnerability_kev_count: int | None = None
    service_count: int | None = None
    account_count: int | None = None
    group_count: int | None = None
    alert_count: int | None = None


class OverviewResponse(BaseModel):
    neo4j: Neo4jHealth
    vector_index: VectorIndexHealth
    model_chain: list[str]
    graph_summary: GraphSummary
    read_only: bool
    checked_at: str
    counts: OverviewCounts


class RiskAssetDrivers(BaseModel):
    """Nhân tử đầu vào của risk_score cao nhất (xem `risk_scoring.compute_risk_score`)."""

    asset_criticality: int
    reachable: bool
    vuln_count: int
    top_cve: str | None = None
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False


class RiskAssetItem(BaseModel):
    canonical_id: str
    hostname: str
    risk_score: float
    cost: float
    patch_priority: float
    drivers: RiskAssetDrivers


class RiskSummary(BaseModel):
    """KPI tính rẻ từ chính list risk — không query thêm gì ngoài risk_scoring."""

    scored_asset_count: int
    high_risk_count: int
    high_risk_threshold: float
    avg_risk_score: float | None = None
    pagerank_wired: bool = False


class RiskResponse(BaseModel):
    items: list[RiskAssetItem]
    summary: RiskSummary


class AlertItem(BaseModel):
    """1 doc thật trong index OpenSearch `security-alerts` — field khớp
    `os_client.ALERTS_MAPPING`. Các field SIEM mở rộng (source_ip...) chỉ có ở
    3 scenario bổ sung (lateral_movement/audit_cleared/new_privilege)."""

    alert_id: str
    orig_alert_id: str | None = None
    time: str
    event_id: int
    success: bool
    outcome: str
    severity: str
    rule: str
    message: str
    computer: str | None = None
    target_user: str | None = None
    asset_canonical_id: str | None = None
    user_canonical_id: str | None = None
    source: str | None = None
    synthetic: bool | None = None
    scenario: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    parent_process: str | None = None
    file_hash: str | None = None
    file_path: str | None = None


class FacetBucket(BaseModel):
    key: str
    doc_count: int


class AlertFacets(BaseModel):
    """Terms agg tính trên CÙNG query đã lọc — không phải thống kê toàn index."""

    asset: list[FacetBucket]
    rule: list[FacetBucket]
    success: list[FacetBucket]


class HistogramBucket(BaseModel):
    date: str
    doc_count: int


class AlertsResponse(BaseModel):
    total: int
    hits: list[AlertItem]
    facets: AlertFacets
    histogram: list[HistogramBucket]


class AttackGraphNode(BaseModel):
    canonical_id: str
    hostname: str
    asset_criticality: int | None = None
    is_entry_point: bool = False
    is_crown_jewel: bool = False


class AttackGraphEdge(BaseModel):
    src: str
    dst: str
    cost: float


class AttackPathItem(BaseModel):
    source: str
    target: str
    total_cost: float
    hops: list[str]


class ChokePointItem(BaseModel):
    canonical_id: str
    hostname: str
    betweenness: float


class PathFrequencyItem(BaseModel):
    canonical_id: str
    count: int


class AttackPathResponse(BaseModel):
    """Đồ thị Asset + CONNECTS_TO + kết quả 3 thuật toán (Dijkstra/BFS/betweenness)
    thật (Giai đoạn 04, `attack_path.run_attack_path`) — dry-run, không ghi Neo4j."""

    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
    entry_points: list[str]
    crown_jewels: list[str]
    paths: list[AttackPathItem]
    choke_points: list[ChokePointItem]
    path_frequency: list[PathFrequencyItem]
    reachable: list[str]
    min_criticality: int
