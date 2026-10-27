"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Box,
  ChevronsUpDown,
  LayoutDashboard,
  Logs,
  MessagesSquare,
  Moon,
  Network,
  ScanEye,
  ShieldAlert,
  Sun,
} from "lucide-react";
import type { HealthResponse } from "@/lib/api";

const NAV_ITEMS = [
  { href: "/overview", label: "Tổng quan", icon: LayoutDashboard, enabled: true },
  { href: "/qa", label: "Hỏi-đáp", icon: MessagesSquare, enabled: true },
  { href: "/graph", label: "Đồ thị", icon: Network, enabled: true },
  { href: "/risk", label: "Risk & Patch", icon: ShieldAlert, enabled: true },
  { href: "/alerts", label: "Alert", icon: Logs, enabled: true },
] as const;

export function Sidebar({
  health,
  loading,
}: {
  health: HealthResponse | null;
  loading: boolean;
}) {
  const pathname = usePathname();
  const scope = health
    ? `${health.graph_summary.asset_count ?? "?"} asset · ${health.graph_summary.user_count ?? "?"} người dùng`
    : loading
      ? "Đang tải phạm vi…"
      : "Không lấy được dữ liệu";

  return (
    <aside className="flex h-full w-[208px] shrink-0 flex-col justify-between overflow-y-auto border-r border-border bg-panel">
      <div className="flex flex-col gap-6">
        <div className="flex h-[72px] items-center gap-[10px] px-5">
          <div className="flex size-7 items-center justify-center rounded-[5px] bg-accent-bg">
            <ScanEye className="size-5 text-accent" />
          </div>
          <div className="leading-tight">
            <p className="text-[18px] font-bold text-text-primary">VECTRA</p>
            <p className="font-mono text-[9px] text-text-muted">EXPOSURE LAB</p>
          </div>
        </div>

        <div className="flex flex-col gap-3.5 px-3">
          <div className="flex items-center gap-[10px] rounded-md border border-border bg-card p-[10px]">
            <Box className="size-4 text-text-secondary" />
            <div className="min-w-0 flex-1 leading-tight">
              <p className="text-[12px] font-semibold text-text-primary">CORP-LAB</p>
              <p className="truncate text-[10px] text-text-secondary">Môi trường nghiên cứu</p>
            </div>
            <ChevronsUpDown className="size-3 shrink-0 text-text-muted" />
          </div>

          <p className="text-[10px] font-semibold text-text-muted">KHÔNG GIAN PHÂN TÍCH</p>

          <nav className="flex flex-col gap-[5px]">
            {NAV_ITEMS.map(({ href, label, icon: Icon, enabled }) => {
              const active = enabled && pathname === href;
              const content = (
                <span
                  className={`flex h-[42px] items-center gap-3 rounded-md px-3 text-[13px] ${
                    active
                      ? "bg-accent-bg font-semibold text-accent"
                      : enabled
                        ? "text-text-secondary hover:bg-card"
                        : "cursor-not-allowed text-text-muted"
                  }`}
                >
                  <Icon className="size-[17px]" />
                  {label}
                  {!enabled && (
                    <span className="ml-auto rounded bg-chip px-[6px] py-[1px] text-[9px] font-semibold text-text-muted">
                      Sắp có
                    </span>
                  )}
                </span>
              );
              return enabled ? (
                <Link key={href} href={href}>
                  {content}
                </Link>
              ) : (
                <span key={href} aria-disabled title="Chưa triển khai trong demo này">
                  {content}
                </span>
              );
            })}
          </nav>
        </div>

        <div className="flex flex-col gap-3 px-6">
          <p className="text-[10px] font-semibold text-text-muted">PHẠM VI ĐANG THEO DÕI</p>
          <p className="font-mono text-[12px] text-text-secondary">{scope}</p>
        </div>
      </div>

      <div className="flex flex-col gap-4 p-4">
        <div className="flex gap-1 rounded-md bg-bg p-1">
          <div className="flex flex-1 items-center justify-center gap-2 rounded bg-chip p-[7px]">
            <Moon className="size-[13px] text-text-primary" />
            <span className="text-[11px] text-text-primary">Tối</span>
          </div>
          <div
            className="flex flex-1 cursor-not-allowed items-center justify-center gap-2 p-[7px] opacity-50"
            title="Theme sáng chưa được thiết kế trong demo này"
          >
            <Sun className="size-[13px] text-text-muted" />
            <span className="text-[11px] text-text-muted">Sáng</span>
          </div>
        </div>
        <p className="font-mono text-[10px] text-text-muted">v0.1.0-lab · demo / chỉ đọc</p>
      </div>
    </aside>
  );
}

export default Sidebar;
