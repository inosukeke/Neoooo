"use client";

import { Circle, CircleDot, TriangleAlert } from "lucide-react";
import type { HealthResponse, Pipeline } from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";

const PIPELINES: { id: Pipeline; label: string; desc: string }[] = [
  {
    id: "text2cypher",
    label: "Text2Cypher",
    desc: "Câu hỏi cấu trúc · truy vấn chính xác theo schema.",
  },
  {
    id: "graphrag",
    label: "GraphRAG",
    desc: "Mô tả ngữ nghĩa · truy hồi node và quan hệ liên quan.",
  },
];

export function PipelinePanel({
  pipeline,
  onChange,
  health,
  healthLoading,
}: {
  pipeline: Pipeline;
  onChange: (p: Pipeline) => void;
  health: HealthResponse | null;
  healthLoading: boolean;
}) {
  const vectorOnline = health?.vector_index.state === "ONLINE";

  return (
    <div className="flex w-[244px] shrink-0 flex-col gap-[14px]">
      <div className="flex flex-col rounded-lg border border-border bg-card">
        <div className="border-b border-border px-4 py-3">
          <span className="text-[13px] font-semibold text-text-primary">Cấu hình truy vấn</span>
        </div>
        <div className="flex flex-col gap-3 p-[14px]">
          <p className="text-[10px] font-semibold text-text-muted">PIPELINE CHO LƯỢT HỎI TIẾP</p>
          {PIPELINES.map((p) => {
            const selected = pipeline === p.id;
            return (
              <button
                type="button"
                key={p.id}
                onClick={() => onChange(p.id)}
                className={`flex flex-col gap-[5px] rounded-md border p-[11px] text-left transition-colors ${
                  selected
                    ? "border-accent-border-strong bg-accent-bg"
                    : "border-border bg-input hover:border-accent-border"
                }`}
              >
                <span className="flex items-center gap-2">
                  {selected ? (
                    <CircleDot className="size-[13px] text-accent" />
                  ) : (
                    <Circle className="size-[13px] text-text-secondary" />
                  )}
                  <span
                    className={`text-[12px] font-semibold ${selected ? "text-accent" : "text-text-primary"}`}
                  >
                    {p.label}
                  </span>
                </span>
                <span className="text-[11px] text-text-secondary">{p.desc}</span>
              </button>
            );
          })}

          <div className="h-px bg-border" />
          <p className="text-[10px] font-semibold text-text-muted">HẠ TẦNG HIỆN TẠI</p>
          <div className="flex items-center justify-between">
            <span className="text-[12px] text-text-primary">Neo4j</span>
            <StatusBadge tone={health?.neo4j.connected ? "success" : "danger"}>
              {healthLoading ? "đang kiểm tra" : health?.neo4j.connected ? "Đã kết nối" : "Mất kết nối"}
            </StatusBadge>
          </div>
          <p className="font-mono text-[10px] text-text-muted">{health?.neo4j.uri ?? "—"}</p>

          <div className="flex items-center justify-between whitespace-nowrap">
            <span className="text-[11px] text-text-secondary">
              {health?.vector_index.name ?? "vector index"}
            </span>
            <span className={`font-mono text-[10px] ${vectorOnline ? "text-success" : "text-warning"}`}>
              {health?.vector_index.state ?? "?"}
            </span>
          </div>

          <div className="h-px bg-border" />
          <p className="text-[10px] font-semibold text-text-muted">MODEL &amp; FALLBACK CHAIN</p>
          {health && health.model_chain.length > 0 ? (
            health.model_chain.map((m, i) => (
              <p
                key={m}
                className={`font-mono text-[11px] ${i === 0 ? "text-text-primary" : "text-text-secondary"}`}
              >
                {i === 0 ? m : `↓ ${m}`}
              </p>
            ))
          ) : (
            <p className="font-mono text-[11px] text-warning">
              Chưa cấu hình LLM_MODEL_CHAIN/TEXT2CYPHER_MODEL
            </p>
          )}
          <p className="text-[10px] text-text-muted">Chuyển model khi lỗi 5xx/429/hết quota.</p>

          <div className="flex items-center justify-between">
            <span
              className="text-[11px] text-text-primary"
              title="Thực thi qua Neo4j session READ-mode — luôn bật, không thể tắt từ UI."
            >
              Chế độ chỉ đọc
            </span>
            <div
              className="flex h-4 w-7 items-start justify-end rounded-full bg-accent p-[2px]"
              aria-label="Luôn bật — không thể tắt"
            >
              <div className="size-3 rounded-md bg-bg" />
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2 rounded-lg border border-border bg-card p-[13px]">
        <div className="flex items-center gap-[6px]">
          <TriangleAlert className="size-[14px] text-warning" />
          <span className="text-[11px] font-semibold text-warning">Trạng thái lỗi minh họa</span>
        </div>
        <p className="text-[12px] font-semibold text-text-primary">Thiếu vector index</p>
        <p className="text-[11px] text-text-secondary">
          GraphRAG dừng trước truy hồi. Tạo <code>vuln_description_embedding</code> rồi thử lại.
        </p>
        <StatusBadge>failed · 34 ms · 0 tokens</StatusBadge>
        <p className="text-[10px] text-text-muted">Ví dụ minh họa — không áp dụng cho phiên đang kết nối.</p>
      </div>

      <div className="flex flex-col gap-[7px] rounded-lg border border-border bg-card p-[13px]">
        <p className="text-[11px] font-semibold text-text-primary">Guardrail · ví dụ chặn ghi</p>
        <p className="font-mono text-[10px] text-text-secondary">&quot;Xóa tất cả node Asset&quot;</p>
        <p className="text-[11px] text-text-secondary">Từ chối DELETE: chỉ cho phép truy vấn đọc.</p>
        <StatusBadge>rejected_write · 12 ms</StatusBadge>
        <p className="font-mono text-[10px] text-text-muted">0 tokens · policy-gate</p>
      </div>
    </div>
  );
}

export default PipelinePanel;
