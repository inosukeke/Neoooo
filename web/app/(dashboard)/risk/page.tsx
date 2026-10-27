"use client";

import { useRisk } from "@/hooks/useRisk";
import { KpiCard } from "@/components/KpiCard";
import { StatusBadge } from "@/components/StatusBadge";
import type { RiskAssetItem } from "@/lib/api";

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score > 0.5 ? "bg-danger" : score > 0.2 ? "bg-warning" : "bg-accent";
  return (
    <div className="flex items-center gap-2">
      <span className="w-9 shrink-0 text-right font-mono text-[11px] text-text-primary">
        {score.toFixed(2)}
      </span>
      <div className="h-[6px] w-16 shrink-0 overflow-hidden rounded-full bg-chip">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function DriverCell({ drivers }: { drivers: RiskAssetItem["drivers"] }) {
  if (!drivers.top_cve) {
    return (
      <span className="text-[11px] text-text-muted">
        {drivers.reachable ? "không có lỗ hổng mở" : "không thể tới (unreachable)"}
      </span>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-[6px]">
      <span className="font-mono text-[11px] text-text-primary">{drivers.top_cve}</span>
      {drivers.in_kev && <StatusBadge tone="danger">KEV</StatusBadge>}
      {!drivers.reachable && <StatusBadge tone="neutral">unreachable</StatusBadge>}
      {drivers.cvss != null && (
        <span className="text-[10px] text-text-muted">CVSS {drivers.cvss.toFixed(1)}</span>
      )}
    </div>
  );
}

export default function RiskPage() {
  const { risk, loading, error } = useRisk();
  const s = risk?.summary;

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-[10px]">
          <h1 className="text-[25px] font-semibold text-text-primary">Risk & Patch</h1>
          <span className="rounded bg-chip px-[7px] py-[2px] text-[11px] font-semibold text-text-secondary">
            DEMO LAB
          </span>
        </div>
        <p className="text-[12px] text-text-secondary">
          Xếp hạng rủi ro thật từ risk_scoring (CVSS × EPSS/KEV × độ nghiêm trọng asset × khả năng
          tiếp cận) — chạy dry-run, không ghi lại đồ thị.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-danger bg-card p-4 text-[12px] text-danger">
          Không lấy được số liệu: {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="ĐÃ CHẤM ĐIỂM" value={loading ? null : (s?.scored_asset_count ?? null)} />
        <KpiCard
          label="RỦI RO TRUNG BÌNH"
          value={loading || s?.avg_risk_score == null ? null : Number(s.avg_risk_score.toFixed(2))}
        />
        <KpiCard
          label="RỦI RO CAO"
          value={loading ? null : (s?.high_risk_count ?? null)}
          sub={s ? `risk_score > ${s.high_risk_threshold}` : undefined}
          tone="danger"
        />
        <div className="flex flex-col gap-1 rounded-lg border border-border bg-card p-4">
          <span className="text-[11px] font-semibold text-text-muted">ƯU TIÊN VÁ</span>
          <StatusBadge tone={s?.pagerank_wired ? "success" : "warning"}>
            {loading ? "đang kiểm tra" : s?.pagerank_wired ? "Đã tính PageRank" : "Chưa tính PageRank"}
          </StatusBadge>
          <span className="text-[10px] text-text-muted">
            patch_priority hiện chỉ phản ánh độ nghiêm trọng asset
          </span>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-[13px] font-semibold text-text-primary">Xếp hạng rủi ro</p>
          {risk && <span className="text-[11px] text-text-muted">{risk.items.length} asset</span>}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="bg-chip text-text-secondary">
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Asset</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Risk score</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Cost</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Patch priority</th>
                <th className="px-3 py-[7px] text-left font-normal whitespace-nowrap">Driver chính</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-text-muted">
                    Đang tải…
                  </td>
                </tr>
              )}
              {!loading && risk?.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-text-muted">
                    Chưa có asset nào được chấm điểm.
                  </td>
                </tr>
              )}
              {risk?.items.map((r) => (
                <tr key={r.canonical_id} className="border-b border-border last:border-0">
                  <td className="px-3 py-[8px] whitespace-nowrap">
                    <div className="flex flex-col">
                      <span className="font-mono text-text-primary">{r.hostname}</span>
                      <span className="text-[10px] text-text-muted">{r.canonical_id}</span>
                    </div>
                  </td>
                  <td className="px-3 py-[8px] whitespace-nowrap">
                    <RiskBar score={r.risk_score} />
                  </td>
                  <td className="px-3 py-[8px] font-mono whitespace-nowrap text-text-primary">
                    {r.cost.toFixed(2)}
                  </td>
                  <td className="px-3 py-[8px] whitespace-nowrap">
                    <span className="font-mono text-text-secondary">{r.patch_priority.toFixed(2)}</span>
                  </td>
                  <td className="px-3 py-[8px]">
                    <DriverCell drivers={r.drivers} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
