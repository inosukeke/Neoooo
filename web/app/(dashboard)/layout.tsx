"use client";

import { useHealth } from "@/hooks/useHealth";
import { Sidebar } from "@/components/Sidebar";
import { Topbar } from "@/components/Topbar";
import { DemoBanner } from "@/components/DemoBanner";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { health, loading, error } = useHealth();

  return (
    <div className="flex h-dvh w-full bg-bg text-text-primary">
      <Sidebar health={health} loading={loading} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar health={health} loading={loading} error={error} />
        <DemoBanner />
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
