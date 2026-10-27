"use client";

import { useMemo, useState } from "react";
import { useAttackPath } from "@/hooks/useAttackPath";
import { AttackGraphCanvas, edgeKey } from "@/components/AttackGraphCanvas";
import { KpiCard } from "@/components/KpiCard";
import { StatusBadge } from "@/components/StatusBadge";

type Mode = "dijkstra" | "bfs" | "betweenness";

const CANVAS_WIDTH = 760;
const CANVAS_HEIGHT = 480;

function hostnameOf(byId: Map<string, string>, id: string): string {
  return byId.get(id) ?? id;
}

export default function GraphPage() {
  const { data, loading, error } = useAttackPath();
  const [mode, setMode] = useState<Mode>("dijkstra");
  const [selectedPathIdx, setSelectedPathIdx] = useState(0);

  const hostnameById = useMemo(
    () => new Map((data?.nodes ?? []).map((n) => [n.canonical_id, n.hostname])),
    [data],
  );
  const reachableSet = useMemo(() => new Set(data?.reachable ?? []), [data]);
  const edgeCost = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of data?.edges ?? []) m.set(edgeKey(e.src, e.dst), e.cost);
    return m;
  }, [data]);

  const selectedPath = data?.paths[selectedPathIdx];

  const highlightNodes = useMemo(() => {
    if (!data) return new Set<string>();
    if (mode === "dijkstra" && selectedPath) return new Set(selectedPath.hops);
    if (mode === "bfs") return new Set(data.reachable);
    if (mode === "betweenness") {
      return new Set(data.choke_points.filter((c) => c.betweenness > 0).map((c) => c.canonical_id));
    }
    return new Set<string>();
  }, [mode, selectedPath, data]);

  const highlightEdges = useMemo(() => {
    const set = new Set<string>();
    if (!data) return set;
    if (mode === "dijkstra" && selectedPath) {
      for (let i = 0; i < selectedPath.hops.length - 1; i++) {
        set.add(edgeKey(selectedPath.hops[i], selectedPath.hops[i + 1]));
      }
    } else if (mode === "bfs") {
      for (const e of data.edges) {
        if (reachableSet.has(e.src) && reachableSet.has(e.dst)) set.add(edgeKey(e.src, e.dst));
      }
    }
    return set;
  }, [mode, selectedPath, data, reachableSet]);

  const nodeScores = useMemo(() => {
    if (mode !== "betweenness" || !data) return undefined;
    return new Map(data.choke_points.map((c) => [c.canonical_id, c.betweenness]));
  }, [mode, data]);

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-[10px]">
          <h1 className="text-[25px] font-semibold text-text-primary">Đồ thị & đường tấn công</h1>
          <span className="rounded bg-chip px-[7px] py-[2px] text-[11px] font-semibold text-text-secondary">
            DEMO LAB
          </span>
        </div>
        <p className="text-[12px] text-text-secondary">
          Dijkstra (cost thấp nhất tới crown jewel) / BFS (reachability) / Betweenness (choke
          point) thật từ GDS (Giai đoạn 04) — dry-run, không ghi Neo4j.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-danger bg-card p-4 text-[12px] text-danger">
          Không lấy được dữ liệu: {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="ENTRY POINT" value={loading ? null : (data?.entry_points.length ?? null)} tone="accent" />
        <KpiCard label="CROWN JEWEL" value={loading ? null : (data?.crown_jewels.length ?? null)} tone="danger" />
        <KpiCard label="ĐƯỜNG TẤN CÔNG" value={loading ? null : (data?.paths.length ?? null)} />
        <KpiCard
          label="ASSET REACHABLE"
          value={loading ? null : (data?.reachable.length ?? null)}
          sub={data ? `trên tổng ${data.nodes.length} asset` : undefined}
        />
      </div>

      <div className="flex gap-1 rounded-md bg-bg p-1 w-fit">
        {(
          [
            ["dijkstra", "Dijkstra (đường rẻ nhất)"],
            ["bfs", "BFS (reachability)"],
            ["betweenness", "Betweenness (choke point)"],
          ] as const
        ).map(([v, label]) => (
          <button
            key={v}
            type="button"
            onClick={() => setMode(v)}
            className={`rounded px-3 py-[6px] text-[11px] font-medium ${
              mode === v ? "bg-chip text-text-primary" : "text-text-muted hover:text-text-secondary"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <div className="rounded-lg border border-border bg-card p-4">
          {loading ? (
            <div className="flex h-[480px] items-center justify-center text-[12px] text-text-muted">
              Đang tải đồ thị…
            </div>
          ) : data ? (
            <>
              <AttackGraphCanvas
                nodes={data.nodes}
                edges={data.edges}
                width={CANVAS_WIDTH}
                height={CANVAS_HEIGHT}
                highlightNodes={highlightNodes}
                highlightEdges={highlightEdges}
                nodeScores={nodeScores}
              />
              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-[10px] text-text-muted">
                <span className="flex items-center gap-[5px]">
                  <span className="size-[9px] rounded-full" style={{ background: "var(--color-danger)" }} />
                  criticality 5
                </span>
                <span className="flex items-center gap-[5px]">
                  <span className="size-[9px] rounded-full" style={{ background: "var(--color-warning)" }} />
                  criticality 4
                </span>
                <span className="flex items-center gap-[5px]">
                  <span className="size-[9px] rounded-full" style={{ background: "var(--color-accent)" }} />
                  criticality 3
                </span>
                <span className="flex items-center gap-[5px]">
                  <span className="size-[9px] rounded-full" style={{ background: "var(--color-text-muted)" }} />
                  criticality ≤2 / chưa gán
                </span>
                <span className="flex items-center gap-[5px]">
                  <span
                    className="size-[9px] rounded-full border-2"
                    style={{ borderColor: "var(--color-accent)" }}
                  />
                  entry point
                </span>
                <span className="flex items-center gap-[5px]">
                  <span
                    className="size-[9px] rounded-full border-2"
                    style={{ borderColor: "var(--color-danger)" }}
                  />
                  crown jewel
                </span>
              </div>
            </>
          ) : null}
        </div>

        <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
          {mode === "dijkstra" && (
            <>
              <p className="text-[12px] font-semibold text-text-primary">
                Xếp hạng đường tấn công (cost thấp = nguy hiểm)
              </p>
              <div className="flex max-h-[220px] flex-col gap-[6px] overflow-y-auto">
                {data?.paths.length === 0 && (
                  <p className="text-[11px] text-text-muted">Không có đường tấn công (không có cặp entry/crown nào nối được).</p>
                )}
                {data?.paths.map((p, i) => (
                  <button
                    key={`${p.source}-${p.target}-${i}`}
                    type="button"
                    onClick={() => setSelectedPathIdx(i)}
                    className={`flex items-center justify-between rounded px-[8px] py-[6px] text-left text-[11px] ${
                      i === selectedPathIdx ? "bg-accent-bg text-accent" : "bg-chip text-text-secondary hover:text-text-primary"
                    }`}
                  >
                    <span className="font-mono">
                      {p.source} → {p.target}
                    </span>
                    <span className="font-mono">{p.total_cost.toFixed(2)}</span>
                  </button>
                ))}
              </div>
              {selectedPath && (
                <>
                  <p className="mt-2 text-[11px] font-semibold text-text-muted">
                    STEP-BY-STEP ({selectedPath.source} → {selectedPath.target})
                  </p>
                  <div className="flex flex-col gap-[4px]">
                    {selectedPath.hops.map((hop, i) => {
                      if (i === 0) {
                        return (
                          <div key={hop} className="flex items-center justify-between text-[11px]">
                            <span className="font-mono text-text-primary">
                              {hop} <span className="text-text-muted">({hostnameOf(hostnameById, hop)})</span>
                            </span>
                            <span className="font-mono text-text-muted">0.00</span>
                          </div>
                        );
                      }
                      const prev = selectedPath.hops[i - 1];
                      const stepCost = edgeCost.get(edgeKey(prev, hop)) ?? 0;
                      const cumulative = selectedPath.hops
                        .slice(1, i + 1)
                        .reduce((acc, h, idx) => acc + (edgeCost.get(edgeKey(selectedPath.hops[idx], h)) ?? 0), 0);
                      return (
                        <div key={hop} className="flex items-center justify-between text-[11px]">
                          <span className="font-mono text-text-primary">
                            → {hop} <span className="text-text-muted">({hostnameOf(hostnameById, hop)})</span>
                          </span>
                          <span className="font-mono text-text-secondary">
                            +{stepCost.toFixed(2)} = {cumulative.toFixed(2)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </>
          )}

          {mode === "bfs" && data && (
            <>
              <p className="text-[12px] font-semibold text-text-primary">
                Reachable từ entry point ({data.reachable.length}/{data.nodes.length})
              </p>
              <div className="flex flex-wrap gap-[6px]">
                {data.reachable.map((id) => (
                  <StatusBadge key={id} tone="accent">
                    {id}
                  </StatusBadge>
                ))}
              </div>
              <p className="mt-2 text-[11px] font-semibold text-text-muted">
                KHÔNG REACHABLE ({data.nodes.length - data.reachable.length})
              </p>
              <div className="flex flex-wrap gap-[6px]">
                {data.nodes
                  .filter((n) => !reachableSet.has(n.canonical_id))
                  .map((n) => (
                    <StatusBadge key={n.canonical_id} tone="neutral">
                      {n.canonical_id}
                    </StatusBadge>
                  ))}
              </div>
            </>
          )}

          {mode === "betweenness" && data && (
            <>
              <p className="text-[12px] font-semibold text-text-primary">
                Choke point (GDS betweenness — theo số bước, mọi cặp, có hướng)
              </p>
              <div className="flex flex-col gap-[6px]">
                {data.choke_points
                  .filter((c) => c.betweenness > 0)
                  .map((c) => (
                    <div key={c.canonical_id} className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-text-primary">
                        {c.canonical_id} <span className="text-text-muted">({c.hostname})</span>
                      </span>
                      <span className="font-mono text-accent">{c.betweenness.toFixed(2)}</span>
                    </div>
                  ))}
                {data.choke_points.every((c) => c.betweenness === 0) && (
                  <p className="text-[11px] text-text-muted">Không có choke point (mọi node betweenness = 0).</p>
                )}
              </div>
              <p className="mt-2 text-[10px] text-text-muted">
                {data.choke_points.filter((c) => c.betweenness === 0).length} asset còn lại có betweenness = 0
                (không nằm trên shortest path nào giữa 2 node khác).
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
