import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";

interface LayoutNode extends SimulationNodeDatum {
  id: string;
}

export interface NodePosition {
  x: number;
  y: number;
}

/**
 * Tính vị trí node bằng d3-force (force-directed), chạy đồng bộ `ticks` bước rồi dừng
 * (không animate) — đồ thị demo nhỏ (~26 node/38 cạnh) nên hội tụ nhanh. Vị trí khởi
 * tạo của d3-force là hàm số góc vàng tất định (không `Math.random`), nên cùng input
 * (thứ tự node/edge) luôn ra cùng layout — an toàn gọi trong `useMemo` khi render.
 */
export function computeForceLayout(
  nodeIds: string[],
  edges: { src: string; dst: string }[],
  width: number,
  height: number,
  ticks = 300,
): Map<string, NodePosition> {
  const nodes: LayoutNode[] = nodeIds.map((id) => ({ id }));
  const links: SimulationLinkDatum<LayoutNode>[] = edges.map((e) => ({
    source: e.src,
    target: e.dst,
  }));

  const simulation = forceSimulation(nodes)
    .force(
      "link",
      forceLink<LayoutNode, SimulationLinkDatum<LayoutNode>>(links)
        .id((d) => d.id)
        .distance(95)
        .strength(0.35),
    )
    .force("charge", forceManyBody().strength(-230))
    .force("center", forceCenter(width / 2, height / 2))
    .force("collide", forceCollide(28))
    .stop();

  for (let i = 0; i < ticks; i++) simulation.tick();

  const positions = new Map<string, NodePosition>();
  const margin = 40;
  for (const n of nodes) {
    positions.set(n.id, {
      x: Math.min(width - margin, Math.max(margin, n.x ?? width / 2)),
      y: Math.min(height - margin, Math.max(margin, n.y ?? height / 2)),
    });
  }
  return positions;
}
