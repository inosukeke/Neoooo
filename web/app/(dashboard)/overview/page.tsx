"use client";

import Link from "next/link";
import { useOverview } from "@/hooks/useOverview";
import { KpiCard } from "@/components/KpiCard";
import { StatusBadge } from "@/components/StatusBadge";

const PIPELINE_STAGES = [
  {
    title: "Thu thập & chuẩn hóa dữ liệu",
    detail: "Nmap/AD/HR (giả lập) + NVD/EPSS/KEV (API thật)",
    done: true,
  },
  {
    title: "Entity resolution",
    detail: "Gộp asset/user trùng giữa nhiều nguồn (55→26 asset, 31→17 user)",
    done: true,
  },
  {
    title: "Đồ thị tri thức (Neo4j + GDS)",
    detail: "Schema v2 — 158 node / 243 relationship",
    done: true,
  },
  {
    title: "Hỏi-đáp LLM (Text2Cypher + GraphRAG)",
    detail: "Có UI — xem trang Hỏi-đáp",
    done: true,
    href: "/qa",
  },
  {
    title: "Risk scoring & Attack path (GDS)",
    detail: "Đã code (src/analysis/) nhưng chưa có API/UI",
    done: false,
  },
  {
    title: "Tìm kiếm alert (OpenSearch)",
    detail: "Đã code (src/search/) nhưng chưa có API/UI",
    done: false,
  },
];

export default function OverviewPage() {
  const { overview, loading, error } = useOverview();
  const c = overview?.counts;

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-[10px]">
          <h1 className="text-[25px] font-semibold text-text-primary">Tổng quan an ninh</h1>
          <span className="rounded bg-chip px-[7px] py-[2px] text-[11px] font-semibold text-text-secondary">
            DEMO LAB
          </span>
        </div>
        <p className="text-[12px] text-text-secondary">
          Số liệu đếm thật từ đồ thị Neo4j hiện tại — không phải số mô phỏng tĩnh.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-danger bg-card p-4 text-[12px] text-danger">
          Không lấy được số liệu: {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="ASSET" value={loading ? null : (c?.asset_count ?? null)} />
        <KpiCard label="NGƯỜI DÙNG" value={loading ? null : (c?.user_count ?? null)} />
        <KpiCard
          label="LỖ HỔNG"
          value={loading ? null : (c?.vulnerability_count ?? null)}
          sub={c ? `trong đó KEV: ${c.vulnerability_kev_count ?? "?"}` : undefined}
          tone="danger"
        />
        <KpiCard label="DỊCH VỤ" value={loading ? null : (c?.service_count ?? null)} />
        <KpiCard label="TÀI KHOẢN" value={loading ? null : (c?.account_count ?? null)} />
        <KpiCard label="NHÓM" value={loading ? null : (c?.group_count ?? null)} />
        <KpiCard label="ALERT" value={loading ? null : (c?.alert_count ?? null)} />
        <div className="flex flex-col gap-1 rounded-lg border border-border bg-card p-4">
          <span className="text-[11px] font-semibold text-text-muted">HẠ TẦNG</span>
          <StatusBadge tone={overview?.neo4j.connected ? "success" : "danger"}>
            {loading ? "đang kiểm tra" : overview?.neo4j.connected ? "Neo4j đã kết nối" : "Mất kết nối"}
          </StatusBadge>
          <span className="text-[10px] text-text-muted">
            vector index: {overview?.vector_index.state ?? "?"}
          </span>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <p className="mb-3 text-[13px] font-semibold text-text-primary">Pipeline (Giai đoạn 01–04)</p>
        <ol className="flex flex-col gap-2">
          {PIPELINE_STAGES.map((s, i) => (
            <li key={s.title} className="flex items-start gap-3">
              <span className="mt-[2px] flex size-5 shrink-0 items-center justify-center rounded-full bg-chip font-mono text-[10px] text-text-secondary">
                {i + 1}
              </span>
              <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2">
                <span className="text-[12px] font-medium text-text-primary">{s.title}</span>
                {s.href ? (
                  <Link href={s.href} className="text-[11px] text-accent hover:underline">
                    {s.detail} ↗
                  </Link>
                ) : (
                  <span className="text-[11px] text-text-secondary">{s.detail}</span>
                )}
                {!s.done && (
                  <span className="rounded bg-chip px-[6px] py-[1px] text-[9px] font-semibold text-text-muted">
                    Sắp có
                  </span>
                )}
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
