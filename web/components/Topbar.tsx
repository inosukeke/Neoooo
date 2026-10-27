"use client";

import { usePathname } from "next/navigation";
import { ChevronDown } from "lucide-react";
import type { HealthResponse } from "@/lib/api";

const PAGE_LABELS: Record<string, string> = {
  "/overview": "Tổng quan",
  "/qa": "Hỏi-đáp",
  "/risk": "Risk & Patch",
  "/alerts": "Alert",
  "/graph": "Đồ thị",
};

export function Topbar({
  health,
  loading,
  error,
}: {
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
}) {
  const pathname = usePathname();
  const pageLabel = PAGE_LABELS[pathname] ?? pathname;
  const connected = health?.neo4j.connected ?? false;
  // `checked_at` đến từ `/health` (state do effect khác set) — render thuần từ
  // props/state có sẵn, không cần effect/setState riêng ở component này.
  const checkedAt = health
    ? new Date(health.checked_at).toLocaleString("vi-VN", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  return (
    <header className="flex h-16 items-center justify-between border-b border-border px-6">
      <div className="flex items-center gap-3 text-[12px]">
        <span className="text-text-muted">Workspace</span>
        <span className="text-text-muted">/</span>
        <span className="text-text-secondary">CORP-LAB</span>
        <span className="text-text-muted">/</span>
        <span className="text-text-primary">{pageLabel}</span>
      </div>
      <div className="flex items-center gap-[18px]">
        <div className="flex items-center gap-[7px]" title={error ?? undefined}>
          <span
            className={`size-[6px] rounded-full ${
              loading ? "bg-text-muted" : connected ? "bg-success" : "bg-danger"
            }`}
          />
          <span className="text-[11px] text-text-secondary">
            {loading
              ? "Đang kiểm tra…"
              : connected
                ? "Hệ thống đã kết nối"
                : "Mất kết nối Neo4j"}
          </span>
        </div>
        {checkedAt && (
          <span className="font-mono text-[11px] text-text-muted" title="Lần kiểm tra /health gần nhất">
            Cập nhật {checkedAt}
          </span>
        )}
        <div className="h-[22px] w-px bg-border" />
        <div className="flex items-center gap-[9px]">
          <div className="flex size-7 items-center justify-center rounded-full bg-chip">
            <span className="text-[10px] font-bold text-text-primary">AN</span>
          </div>
          <span className="text-[12px] text-text-primary">Analyst</span>
          <ChevronDown className="size-3 text-text-muted" />
        </div>
      </div>
    </header>
  );
}

export default Topbar;
