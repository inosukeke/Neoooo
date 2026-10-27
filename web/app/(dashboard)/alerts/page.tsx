"use client";

import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { useAlerts } from "@/hooks/useAlerts";
import { KpiCard } from "@/components/KpiCard";
import { StatusBadge } from "@/components/StatusBadge";
import type { AlertsQuery, HistogramBucket } from "@/lib/api";

function severityTone(severity: string): "neutral" | "danger" | "warning" {
  if (severity === "critical") return "danger";
  if (severity === "high") return "warning";
  return "neutral";
}

function shortDate(iso: string): string {
  const d = new Date(iso);
  return `${String(d.getUTCDate()).padStart(2, "0")}/${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

function shortTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function Histogram({ buckets }: { buckets: HistogramBucket[] }) {
  if (buckets.length === 0) {
    return <p className="text-[11px] text-text-muted">Không có dữ liệu theo ngày.</p>;
  }
  const max = Math.max(1, ...buckets.map((b) => b.doc_count));
  return (
    <div className="flex h-[88px] items-end gap-[3px]">
      {buckets.map((b) => (
        <div
          key={b.date}
          className="flex h-full flex-1 flex-col items-center justify-end gap-1"
          title={`${shortDate(b.date)}: ${b.doc_count} alert`}
        >
          <div
            className="w-full rounded-t bg-accent/70"
            style={{ height: `${Math.max(4, (b.doc_count / max) * 100)}%` }}
          />
          <span className="text-[9px] text-text-muted">{shortDate(b.date)}</span>
        </div>
      ))}
    </div>
  );
}

function FacetChips({
  title,
  buckets,
  selected,
  onToggle,
}: {
  title: string;
  buckets: { key: string; doc_count: number }[];
  selected?: string;
  onToggle: (key: string) => void;
}) {
  return (
    <div className="flex flex-col gap-2">
      <span className="text-[10px] font-semibold text-text-muted">{title}</span>
      <div className="flex flex-wrap gap-[6px]">
        {buckets.length === 0 && <span className="text-[11px] text-text-muted">—</span>}
        {buckets.map((b) => (
          <button
            key={b.key}
            type="button"
            onClick={() => onToggle(b.key)}
            className={`rounded px-[8px] py-[3px] text-[11px] font-mono transition-colors ${
              selected === b.key
                ? "bg-accent-bg text-accent"
                : "bg-chip text-text-secondary hover:text-text-primary"
            }`}
          >
            {b.key} <span className="text-text-muted">({b.doc_count})</span>
          </button>
        ))}
      </div>
    </div>
  );
}

export default function AlertsPage() {
  const [textInput, setTextInput] = useState("");
  const [appliedText, setAppliedText] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<string | undefined>(undefined);
  const [selectedRule, setSelectedRule] = useState<string | undefined>(undefined);
  const [successFilter, setSuccessFilter] = useState<"all" | "success" | "fail">("all");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [size, setSize] = useState(50);

  useEffect(() => {
    const t = setTimeout(() => setAppliedText(textInput.trim()), 400);
    return () => clearTimeout(t);
  }, [textInput]);

  const query: AlertsQuery = useMemo(
    () => ({
      text: appliedText || undefined,
      asset_canonical_id: selectedAsset,
      rule: selectedRule,
      success: successFilter === "all" ? undefined : successFilter === "success",
      start: startDate ? `${startDate}T00:00:00Z` : undefined,
      end: endDate ? `${endDate}T23:59:59Z` : undefined,
      size,
      from: 0,
    }),
    [appliedText, selectedAsset, selectedRule, successFilter, startDate, endDate, size],
  );

  const { alerts, loading, error } = useAlerts(query);
  const failedCount = alerts?.facets.success.find((b) => b.key === "false")?.doc_count ?? null;
  const successCount = alerts?.facets.success.find((b) => b.key === "true")?.doc_count ?? null;
  const topAsset = alerts?.facets.asset[0];
  const hasActiveFilter =
    !!appliedText || !!selectedAsset || !!selectedRule || successFilter !== "all" || !!startDate || !!endDate;

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-[10px]">
          <h1 className="text-[25px] font-semibold text-text-primary">Alert & tìm kiếm log</h1>
          <span className="rounded bg-chip px-[7px] py-[2px] text-[11px] font-semibold text-text-secondary">
            DEMO LAB
          </span>
        </div>
        <p className="text-[12px] text-text-secondary">
          Full-text + facet + histogram thật trên index OpenSearch <code>security-alerts</code> (1653
          doc nhân bản từ 30 alert gốc).
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-danger bg-card p-4 text-[12px] text-danger">
          Không lấy được dữ liệu: {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="ALERT KHỚP BỘ LỌC" value={loading ? null : (alerts?.total ?? null)} />
        <KpiCard
          label="THẤT BẠI"
          value={loading ? null : failedCount}
          tone="danger"
        />
        <KpiCard label="THÀNH CÔNG" value={loading ? null : successCount} tone="success" />
        <div className="flex flex-col gap-1 rounded-lg border border-border bg-card p-4">
          <span className="text-[11px] font-semibold text-text-muted">ASSET NỔI BẬT NHẤT</span>
          {loading ? (
            <span className="font-mono text-[18px] text-text-primary">—</span>
          ) : topAsset ? (
            <>
              <span className="font-mono text-[18px] font-semibold text-text-primary">{topAsset.key}</span>
              <span className="text-[10px] text-text-muted">{topAsset.doc_count} alert khớp bộ lọc</span>
            </>
          ) : (
            <span className="text-[11px] text-text-muted">Không có alert</span>
          )}
        </div>
      </div>

      <div className="flex flex-col gap-4 rounded-lg border border-border bg-card p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="flex flex-1 items-center gap-2 rounded-[5px] border border-border bg-input px-3 py-[7px]">
            <Search className="size-[14px] text-text-muted" />
            <input
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder="Tìm trong message (full-text)…"
              className="w-full bg-transparent text-[12px] text-text-primary placeholder:text-text-muted focus:outline-none"
            />
          </div>
          <div className="flex gap-1 rounded-md bg-bg p-1">
            {(["all", "success", "fail"] as const).map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => setSuccessFilter(v)}
                className={`rounded px-3 py-[6px] text-[11px] font-medium ${
                  successFilter === v ? "bg-chip text-text-primary" : "text-text-muted hover:text-text-secondary"
                }`}
              >
                {v === "all" ? "Tất cả" : v === "success" ? "Thành công" : "Thất bại"}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 text-[11px] text-text-secondary">
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="rounded border border-border bg-input px-2 py-[5px] text-text-primary"
            />
            <span className="text-text-muted">→</span>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="rounded border border-border bg-input px-2 py-[5px] text-text-primary"
            />
          </div>
          {hasActiveFilter && (
            <button
              type="button"
              onClick={() => {
                setTextInput("");
                setAppliedText("");
                setSelectedAsset(undefined);
                setSelectedRule(undefined);
                setSuccessFilter("all");
                setStartDate("");
                setEndDate("");
              }}
              className="text-[11px] text-accent hover:underline"
            >
              Xóa bộ lọc
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FacetChips
            title="ASSET (top 10 theo bộ lọc hiện tại)"
            buckets={alerts?.facets.asset ?? []}
            selected={selectedAsset}
            onToggle={(k) => setSelectedAsset(selectedAsset === k ? undefined : k)}
          />
          <FacetChips
            title="RULE (top 10 theo bộ lọc hiện tại)"
            buckets={alerts?.facets.rule ?? []}
            selected={selectedRule}
            onToggle={(k) => setSelectedRule(selectedRule === k ? undefined : k)}
          />
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-[10px] font-semibold text-text-muted">
            SỐ ALERT THEO NGÀY (date histogram, theo bộ lọc hiện tại)
          </span>
          <Histogram buckets={alerts?.histogram ?? []} />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-[13px] font-semibold text-text-primary">Danh sách alert</p>
          <span className="text-[11px] text-text-muted">
            Hiện {alerts?.hits.length ?? 0} / {alerts?.total ?? 0} (mới nhất trước)
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="bg-chip text-text-secondary">
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Thời gian</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Asset</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Tài khoản</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Rule</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Severity</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Kết quả</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-text-muted">
                    Đang tải…
                  </td>
                </tr>
              )}
              {!loading && alerts?.hits.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-text-muted">
                    Không có alert khớp bộ lọc.
                  </td>
                </tr>
              )}
              {alerts?.hits.map((a) => (
                <tr key={a.alert_id} className="border-b border-border last:border-0">
                  <td className="px-3 py-[8px] font-mono whitespace-nowrap text-text-secondary">
                    {shortTime(a.time)}
                  </td>
                  <td className="px-3 py-[8px] font-mono whitespace-nowrap text-text-primary">
                    {a.asset_canonical_id ?? a.computer ?? "—"}
                  </td>
                  <td className="px-3 py-[8px] whitespace-nowrap text-text-primary">
                    {a.target_user ?? "—"}
                  </td>
                  <td className="px-3 py-[8px] text-text-secondary">{a.rule}</td>
                  <td className="px-3 py-[8px] whitespace-nowrap">
                    <StatusBadge tone={severityTone(a.severity)}>{a.severity}</StatusBadge>
                  </td>
                  <td className="px-3 py-[8px] whitespace-nowrap">
                    <StatusBadge tone={a.success ? "success" : "danger"}>{a.outcome}</StatusBadge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {alerts && alerts.hits.length < alerts.total && alerts.hits.length === size && (
          <div className="mt-3 flex justify-center">
            <button
              type="button"
              onClick={() => setSize((s) => Math.min(200, s + 50))}
              className="rounded border border-border bg-chip px-4 py-[6px] text-[11px] text-text-secondary hover:text-text-primary"
            >
              Tải thêm
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
