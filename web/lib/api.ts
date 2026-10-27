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

export function askQuestion(pipeline: Pipeline, question: string): Promise<AskAnswer> {
  return request<AskAnswer>("/ask", {
    method: "POST",
    body: JSON.stringify({ pipeline, question }),
  });
}
