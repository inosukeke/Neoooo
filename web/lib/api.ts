/**
 * Fetch wrapper gọi FastAPI backend (`src/api/main.py`). Không có state/session
 * phía server — mỗi `askQuestion` là 1 request độc lập, khớp đúng cách
 * Text2Cypher/GraphRAG xử lý ở backend (không nhớ ngữ cảnh đa lượt).
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type Pipeline = "text2cypher" | "graphrag";

export interface Text2CypherAnswer {
  pipeline: "text2cypher";
  question: string;
  status: "ok" | "rejected_write" | "failed";
  answer: string;
  cypher: string | null;
  rows: Record<string, unknown>[];
  errors: string[];
  attempts: number;
  fixes: string[];
  latency_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  model: string;
}

export interface RetrievedSource {
  id: string;
  score: number | null;
  data: Record<string, unknown>;
}

export interface GraphRAGAnswer {
  pipeline: "graphrag";
  question: string;
  answer: string;
  sources: RetrievedSource[];
  seed_ids: unknown[];
  latency_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  model: string;
}

export type AskAnswer = Text2CypherAnswer | GraphRAGAnswer;

export interface HealthResponse {
  neo4j: { connected: boolean; uri: string; error: string | null };
  vector_index: { name: string; state: string; error: string | null };
  model_chain: string[];
  graph_summary: { asset_count: number | null; user_count: number | null };
  read_only: boolean;
  checked_at: string;
}

export interface OverviewCounts {
  asset_count: number | null;
  user_count: number | null;
  vulnerability_count: number | null;
  vulnerability_kev_count: number | null;
  service_count: number | null;
  account_count: number | null;
  group_count: number | null;
  alert_count: number | null;
}

export interface OverviewResponse extends HealthResponse {
  counts: OverviewCounts;
}

export interface RiskAssetDrivers {
  asset_criticality: number;
  reachable: boolean;
  vuln_count: number;
  top_cve: string | null;
  cvss: number | null;
  epss: number | null;
  in_kev: boolean;
}

export interface RiskAssetItem {
  canonical_id: string;
  hostname: string;
  risk_score: number;
  cost: number;
  patch_priority: number;
  drivers: RiskAssetDrivers;
}

export interface RiskSummary {
  scored_asset_count: number;
  high_risk_count: number;
  high_risk_threshold: number;
  avg_risk_score: number | null;
  pagerank_wired: boolean;
}

export interface RiskResponse {
  items: RiskAssetItem[];
  summary: RiskSummary;
}

export interface AlertItem {
  alert_id: string;
  orig_alert_id: string | null;
  time: string;
  event_id: number;
  success: boolean;
  outcome: string;
  severity: string;
  rule: string;
  message: string;
  computer: string | null;
  target_user: string | null;
  asset_canonical_id: string | null;
  user_canonical_id: string | null;
  source: string | null;
  synthetic: boolean | null;
  scenario: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  source_port: number | null;
  dest_port: number | null;
  process_name: string | null;
  process_path: string | null;
  parent_process: string | null;
  file_hash: string | null;
  file_path: string | null;
}

export interface FacetBucket {
  key: string;
  doc_count: number;
}

export interface AlertFacets {
  asset: FacetBucket[];
  rule: FacetBucket[];
  success: FacetBucket[];
}

export interface HistogramBucket {
  date: string;
  doc_count: number;
}

export interface AlertsResponse {
  total: number;
  hits: AlertItem[];
  facets: AlertFacets;
  histogram: HistogramBucket[];
}

export interface AlertsQuery {
  text?: string;
  asset_canonical_id?: string;
  rule?: string;
  success?: boolean;
  start?: string;
  end?: string;
  size?: number;
  from?: number;
}

export interface AttackGraphNode {
  canonical_id: string;
  hostname: string;
  asset_criticality: number | null;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
}

export interface AttackGraphEdge {
  src: string;
  dst: string;
  cost: number;
}

export interface AttackPathItem {
  source: string;
  target: string;
  total_cost: number;
  hops: string[];
}

export interface ChokePointItem {
  canonical_id: string;
  hostname: string;
  betweenness: number;
}

export interface PathFrequencyItem {
  canonical_id: string;
  count: number;
}

export interface AttackPathResponse {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  entry_points: string[];
  crown_jewels: string[];
  paths: AttackPathItem[];
  choke_points: ChokePointItem[];
  path_frequency: PathFrequencyItem[];
  reachable: string[];
  min_criticality: number;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(
      `Không gọi được API tại ${API_BASE} — kiểm tra backend FastAPI (uvicorn) đang chạy.`,
      0,
    );
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { detail?: string };
      detail = body.detail ?? detail;
    } catch {
      // body không phải JSON — giữ statusText
    }
    throw new ApiError(detail, res.status);
  }
  return (await res.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function getOverview(): Promise<OverviewResponse> {
  return request<OverviewResponse>("/overview");
}

export function getRisk(): Promise<RiskResponse> {
  return request<RiskResponse>("/risk");
}

export function askQuestion(pipeline: Pipeline, question: string): Promise<AskAnswer> {
  return request<AskAnswer>("/ask", {
    method: "POST",
    body: JSON.stringify({ pipeline, question }),
  });
}

export function getAlerts(query: AlertsQuery = {}): Promise<AlertsResponse> {
  const params = new URLSearchParams();
  if (query.text) params.set("text", query.text);
  if (query.asset_canonical_id) params.set("asset_canonical_id", query.asset_canonical_id);
  if (query.rule) params.set("rule", query.rule);
  if (query.success !== undefined) params.set("success", String(query.success));
  if (query.start) params.set("start", query.start);
  if (query.end) params.set("end", query.end);
  params.set("size", String(query.size ?? 20));
  params.set("from", String(query.from ?? 0));
  return request<AlertsResponse>(`/alerts?${params.toString()}`);
}

export function getAttackPath(minCriticality = 4): Promise<AttackPathResponse> {
  return request<AttackPathResponse>(`/attack-path?min_criticality=${minCriticality}`);
}
