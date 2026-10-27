"use client";

import { ArrowUp } from "lucide-react";
import type { Pipeline } from "@/lib/api";

export function Composer({
  value,
  onChange,
  onSend,
  busy,
  pipeline,
  suggestions,
  onPickSuggestion,
}: {
  value: string;
  onChange: (v: string) => void;
  onSend: () => void;
  busy: boolean;
  pipeline: Pipeline;
  suggestions: Record<Pipeline, string>;
  onPickSuggestion: (q: string) => void;
}) {
  return (
    <div className="flex flex-col gap-[9px]">
      <div className="flex flex-col gap-2 rounded-lg border border-accent-border-strong bg-card p-[14px]">
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              onSend();
            }
          }}
          rows={1}
          placeholder="Hỏi tiếp về asset, lỗ hổng hoặc đường tấn công…"
          className="w-full resize-none bg-transparent text-[13px] text-text-primary placeholder:text-text-secondary focus:outline-none"
          disabled={busy}
        />
        <div className="flex items-center justify-between gap-3">
          <span className="text-[10px] text-text-muted">
            {pipeline === "text2cypher" ? "Text2Cypher" : "GraphRAG"} · Mỗi câu hỏi xử lý độc lập,
            không lưu ngữ cảnh hội thoại
          </span>
          <button
            type="button"
            onClick={onSend}
            disabled={busy || !value.trim()}
            className="flex shrink-0 items-center gap-2 rounded-md border border-accent-border bg-accent-bg px-[10px] py-[6px] text-[12px] font-medium text-accent disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowUp className="size-[14px]" /> {busy ? "Đang gửi…" : "Gửi câu hỏi"}
          </button>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-[10px] text-[10px]">
        <span className="text-text-muted">Gợi ý</span>
        {Object.values(suggestions).map((q) => (
          <button
            key={q}
            type="button"
            onClick={() => onPickSuggestion(q)}
            disabled={busy}
            className="text-text-secondary hover:text-accent disabled:cursor-not-allowed disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>
    </div>
  );
}

export default Composer;
