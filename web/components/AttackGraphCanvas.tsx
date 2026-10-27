"use client";

import { useMemo } from "react";
import { computeForceLayout } from "@/lib/forceLayout";
import type { AttackGraphEdge, AttackGraphNode } from "@/lib/api";

function criticalityColor(c: number | null): string {
  if (c == null) return "var(--color-text-muted)";
  if (c >= 5) return "var(--color-danger)";
  if (c === 4) return "var(--color-warning)";
  if (c === 3) return "var(--color-accent)";
  return "var(--color-text-muted)";
}

export function edgeKey(src: string, dst: string): string {
  return `${src}->${dst}`;
}

export function AttackGraphCanvas({
  nodes,
  edges,
  width,
  height,
  highlightNodes,
  highlightEdges,
  nodeScores,
}: {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  width: number;
  height: number;
  highlightNodes: Set<string>;
  highlightEdges: Set<string>;
  /** canonical_id -> điểm phụ (vd betweenness) để phóng to node nổi bật, tuỳ chọn. */
  nodeScores?: Map<string, number>;
}) {
  const positions = useMemo(
    () => computeForceLayout(nodes.map((n) => n.canonical_id), edges, width, height),
    [nodes, edges, width, height],
  );
  const maxScore = useMemo(
    () => (nodeScores ? Math.max(1e-6, ...nodeScores.values()) : 1),
    [nodeScores],
  );

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      role="img"
      aria-label="Đồ thị Asset và đường tấn công"
    >
      <g>
        {edges.map((e) => {
          const s = positions.get(e.src);
          const t = positions.get(e.dst);
          if (!s || !t) return null;
          const highlighted = highlightEdges.has(edgeKey(e.src, e.dst));
          return (
            <line
              key={`${e.src}-${e.dst}`}
              x1={s.x}
              y1={s.y}
              x2={t.x}
              y2={t.y}
              style={{
                stroke: highlighted ? "var(--color-danger)" : "var(--color-border)",
                strokeWidth: highlighted ? 2.5 : 1,
                opacity: highlighted ? 0.95 : 0.5,
              }}
            >
              <title>
                {e.src} → {e.dst} (cost {e.cost.toFixed(2)})
              </title>
            </line>
          );
        })}
      </g>
      <g>
        {nodes.map((n) => {
          const p = positions.get(n.canonical_id);
          if (!p) return null;
          const highlighted = highlightNodes.has(n.canonical_id);
          const score = nodeScores?.get(n.canonical_id) ?? 0;
          const baseRadius = 9 + (nodeScores ? (score / maxScore) * 10 : 0);
          const radius = highlighted ? baseRadius + 2 : baseRadius;
          return (
            <g key={n.canonical_id}>
              <circle
                cx={p.x}
                cy={p.y}
                r={radius}
                style={{
                  fill: criticalityColor(n.asset_criticality),
                  fillOpacity: highlighted ? 1 : 0.55,
                  stroke: n.is_crown_jewel
                    ? "var(--color-danger)"
                    : n.is_entry_point
                      ? "var(--color-accent)"
                      : "var(--color-border)",
                  strokeWidth: n.is_crown_jewel || n.is_entry_point ? 2.5 : 1,
                }}
              >
                <title>
                  {n.hostname} ({n.canonical_id}) — criticality {n.asset_criticality ?? "?"}
                  {n.is_entry_point ? " · entry point" : ""}
                  {n.is_crown_jewel ? " · crown jewel" : ""}
                  {nodeScores ? ` · betweenness ${score.toFixed(2)}` : ""}
                </title>
              </circle>
              <text
                x={p.x}
                y={p.y + radius + 11}
                textAnchor="middle"
                style={{
                  fill: highlighted ? "var(--color-text-primary)" : "var(--color-text-muted)",
                  fontSize: 9,
                  fontFamily: "var(--font-mono, monospace)",
                }}
              >
                {n.hostname}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}

export default AttackGraphCanvas;
