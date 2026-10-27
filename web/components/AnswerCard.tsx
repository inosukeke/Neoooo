"use client";

import { Copy, ScanEye, TriangleAlert } from "lucide-react";
import type { AskAnswer, GraphRAGAnswer, Pipeline, Text2CypherAnswer } from "@/lib/api";

export interface Turn {
  id: string;
  question: string;
  pipeline: Pipeline;
  askedAt: string;
  status: "pending" | "done" | "error";
  answer?: AskAnswer;
  errorMessage?: string;
}

const STATUS_TONE: Record<string, string> = {
  ok: "bg-chip text-text-secondary",
  rejected_write: "bg-chip text-warning",
  failed: "bg-danger-bg text-danger",
};

function ResponseMeta({
  status,
  latencyMs,
  tokens,
  model,
}: {
  status?: string;
  latencyMs: number;
  tokens: number;
  model: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {status && (
        <span
          className={`rounded px-[7px] py-[2px] text-[11px] font-semibold ${STATUS_TONE[status] ?? "bg-chip text-text-secondary"}`}
        >
          {status}
        </span>
      )}
      <span className="font-mono text-[10px] text-text-muted">
        {latencyMs} ms · {tokens} tokens · {model || "(model chưa cấu hình)"}
      </span>
      <span className="text-[10px] text-text-muted">· Chỉ đọc · Có bằng chứng</span>
    </div>
  );
}

function CypherBlock({ cypher }: { cypher: string }) {
  const copy = () => {
    navigator.clipboard?.writeText(cypher).catch(() => {});
  };
  return (
    <div className="flex min-w-0 flex-1 flex-col rounded-[5px] border border-border bg-input">
      <div className="flex items-center justify-between border-b border-border px-3 py-[7px]">
        <span className="text-[11px] font-semibold text-accent">Cypher sinh ra</span>
        <button
          type="button"
          onClick={copy}
          title="Sao chép"
          className="text-text-muted hover:text-text-primary"
        >
          <Copy className="size-3" />
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[10px] leading-[1.8] whitespace-pre-wrap text-text-secondary">
        {cypher}
      </pre>
    </div>
  );
}

function ResultTable({ rows }: { rows: Record<string, unknown>[] }) {
  if (rows.length === 0) {
    return (
      <div className="flex-1 rounded-[5px] border border-border bg-input p-3 text-[11px] text-text-muted">
        Không có dòng kết quả.
      </div>
    );
  }
  const columns = Object.keys(rows[0]);
  return (
    <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-[5px] border border-border bg-input">
      <div className="flex items-center justify-between px-3 py-[7px]">
        <span className="text-[11px] font-semibold text-accent">Kết quả</span>
        <span className="text-[10px] text-text-muted">{rows.length} dòng</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[10px]">
          <thead>
            <tr className="bg-chip text-text-secondary">
              {columns.map((c) => (
                <th key={c} className="px-3 py-[6px] text-left font-normal whitespace-nowrap">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-border last:border-0">
                {columns.map((c) => (
                  <td key={c} className="px-3 py-[6px] whitespace-nowrap text-text-primary">
                    {String(row[c] ?? "")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AssistantHeader({ badge }: { badge: string }) {
  return (
    <div className="flex items-center gap-2">
      <ScanEye className="size-4 text-text-primary" />
      <span className="text-[11px] font-semibold text-text-primary">VECTRA</span>
      <span className="rounded bg-accent-bg px-[7px] py-[2px] text-[11px] font-semibold text-accent">
        {badge}
      </span>
    </div>
  );
}

function Text2CypherBody({ a }: { a: Text2CypherAnswer }) {
  return (
    <div className="flex flex-col gap-[10px] rounded-lg border border-border bg-card p-4">
      <AssistantHeader badge="Text2Cypher" />
      <p className="text-[14px] font-semibold text-text-primary">{a.answer}</p>
      {a.cypher && (
        <div className="flex flex-col gap-3 sm:flex-row">
          <CypherBlock cypher={a.cypher} />
          <ResultTable rows={a.rows} />
        </div>
      )}
      <ResponseMeta
        status={a.status}
        latencyMs={a.latency_ms}
        tokens={a.prompt_tokens + a.completion_tokens}
        model={a.model}
      />
    </div>
  );
}

function GraphRAGBody({ a }: { a: GraphRAGAnswer }) {
  return (
    <div className="flex flex-col gap-[10px] rounded-lg border border-border bg-card p-4">
      <AssistantHeader badge="GraphRAG" />
      <p className="text-[14px] font-semibold text-text-primary">{a.answer}</p>
      {a.sources.length > 0 && (
        <>
          <div className="flex items-center gap-5 py-[5px] text-[11px]">
            <span className="font-semibold text-accent">Ngữ cảnh truy hồi</span>
            <span className="text-text-muted">Kết quả · {a.sources.length} nguồn</span>
          </div>
          <div className="flex flex-col gap-[10px] sm:flex-row sm:flex-wrap">
            {a.sources.map((s) => (
              <div
                key={s.id}
                className="flex min-w-[220px] flex-1 flex-col gap-1 rounded border border-border bg-input p-[10px]"
              >
                <div className="flex items-center justify-between font-mono text-[10px]">
                  <span className="text-text-primary">{s.id}</span>
                  {s.score != null && <span className="text-accent">similarity {s.score.toFixed(3)}</span>}
                </div>
                <p className="text-[10px] text-text-secondary">
                  {Object.entries(s.data)
                    .filter(([k]) => k !== "id")
                    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`)
                    .join(" · ")}
                </p>
              </div>
            ))}
          </div>
        </>
      )}
      <ResponseMeta
        latencyMs={a.latency_ms}
        tokens={a.prompt_tokens + a.completion_tokens}
        model={a.model}
      />
    </div>
  );
}

export function AnswerCard({ turn }: { turn: Turn }) {
  if (turn.status === "pending") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-border bg-card p-4 text-[12px] text-text-muted">
        <ScanEye className="size-4 animate-pulse" /> Đang chạy{" "}
        {turn.pipeline === "text2cypher" ? "Text2Cypher" : "GraphRAG"}…
      </div>
    );
  }
  if (turn.status === "error") {
    return (
      <div className="flex flex-col gap-2 rounded-lg border border-danger bg-card p-4">
        <div className="flex items-center gap-2">
          <TriangleAlert className="size-4 text-warning" />
          <span className="text-[12px] font-semibold text-text-primary">Không lấy được câu trả lời</span>
        </div>
        <p className="text-[12px] text-text-secondary">{turn.errorMessage}</p>
        <p className="text-[10px] text-text-muted">
          Kiểm tra: backend FastAPI (uvicorn) đang chạy, Neo4j đã nạp pipeline, env LLM gateway trong{" "}
          <code>.env</code> (GraphRAG cần vector index <code>vuln_description_embedding</code>).
        </p>
      </div>
    );
  }
  if (!turn.answer) return null;
  return turn.answer.pipeline === "text2cypher" ? (
    <Text2CypherBody a={turn.answer} />
  ) : (
    <GraphRAGBody a={turn.answer} />
  );
}

export default AnswerCard;
