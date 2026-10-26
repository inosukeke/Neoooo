"""Dự đoán đường tấn công (Giai đoạn 04) — Dijkstra + BFS + betweenness trên GDS.

Quy trình: tìm entry point (Service exposure='public') và crown jewel
(asset_criticality >= ngưỡng) -> Dijkstra theo ``cost`` cho từng cặp -> betweenness
trên đồ thị con gồm các node nằm trên attack path -> bảng xếp hạng đường + choke point.

Choke point có hai tín hiệu BỔ SUNG nhau: ``choke_points`` (GDS betweenness: unweighted,
mọi cặp, có hướng) và ``path_frequency`` (đếm node trên các path Dijkstra theo cost).

GIẢ ĐỊNH: ``risk_scoring.py`` đã chạy trước, tức là ``exposure`` (Service),
``asset_criticality`` (Asset) và ``CONNECTS_TO.cost`` đã được ghi. Module này chỉ ĐỌC các
property đó (business context gán tay, không suy từ Nmap/CVE); cạnh thiếu/sai ``cost`` thì
báo lỗi rõ ràng (``MissingCostError``), KHÔNG tự bịa cost.

BFS (ít bước, ``reachable_from_entries``) KHÁC Dijkstra (cost thấp, ``shortest_attack_paths``):
hai thuật toán có thể cho hai đường khác nhau.

GDS: project/Dijkstra/BFS-có-maxDepth trùng cú pháp ``algo_demo.py`` (đã chạy thật GDS
2.13.13). CHƯA verify trên GDS thật: ``gds.betweenness.stream``, project đồ thị con
(``WHERE ... IN $ids``), ``gds.bfs.stream`` không maxDepth, và chính module này nói chung.
Bản chiếu là bản chụp: drop nếu tồn tại rồi project lại (idempotent), và drop sau khi xong.

Bảo mật: mọi Cypher/GDS call dùng tham số ($param); attack path graph là tài liệu nhạy
cảm nhất — module không log đường đi, chỉ in ra stdout khi CLI được chạy chủ động.

Chạy thật (cần Neo4j + GDS, đã chạy load_graph.py và risk_scoring.py):
    python src/analysis/attack_path/attack_path.py --top 10
"""

import argparse
import os
import sys
import uuid
from collections import Counter
from dataclasses import dataclass

# Tên gốc bản chiếu GDS (bản chụp). run_attack_path thêm hậu tố ngẫu nhiên để hai lần chạy
# đồng thời không giẫm nhau, và drop sau khi xong (đồ thị cost là tài liệu nhạy cảm).
GRAPH_FULL = "attack_path_full"
GRAPH_SUB = "attack_path_sub"


class MissingCostError(RuntimeError):
    """Có cạnh CONNECTS_TO thiếu ``cost`` hoặc cost không hợp lệ (sai kiểu / âm)."""


@dataclass
class AttackPath:
    source: str
    target: str
    total_cost: float
    hops: list[str]


@dataclass
class ChokePoint:
    hostname: str
    canonical_id: str
    betweenness: float


# ---------- Cypher / GDS (parameterized) ----------
ENTRY_POINTS_QUERY = """MATCH (a:Asset)-[:RUNS]->(s:Service {exposure: $exposure})
RETURN DISTINCT a.canonical_id AS canonical_id
ORDER BY canonical_id"""

CROWN_JEWELS_QUERY = """MATCH (a:Asset)
WHERE a.asset_criticality >= $min_criticality
RETURN a.canonical_id AS canonical_id
ORDER BY canonical_id"""

# cost phải là số (INTEGER/FLOAT) và >= 0: Dijkstra không nhận trọng số âm.
MISSING_COST_QUERY = """MATCH (:Asset)-[r:CONNECTS_TO]->(:Asset)
WHERE r.cost IS NULL
   OR NOT (r.cost IS :: FLOAT OR r.cost IS :: INTEGER)
   OR r.cost < 0
RETURN count(r) AS missing"""

# Tập node THỰC SỰ nằm trong bản chiếu full (asset có >= 1 cạnh CONNECTS_TO giữa 2 Asset).
PROJECTED_NODES_QUERY = """MATCH (a:Asset)-[:CONNECTS_TO]-(:Asset)
RETURN DISTINCT a.canonical_id AS canonical_id"""

GRAPH_EXISTS_QUERY = "CALL gds.graph.exists($name) YIELD exists RETURN exists"
GRAPH_DROP_QUERY = "CALL gds.graph.drop($name) YIELD graphName RETURN graphName"

# Chiếu có hướng + trọng số cost (cú pháp trùng algo_demo.py, đã chạy thật GDS 2.13.13).
PROJECT_FULL_QUERY = """MATCH (s:Asset)-[r:CONNECTS_TO]->(t:Asset)
WITH gds.graph.project($name, s, t, {relationshipProperties: r {.cost}}) AS g
RETURN g.nodeCount AS nodes, g.relationshipCount AS rels"""

# Đồ thị con: chỉ cạnh có cả hai đầu nằm trong $ids (CHƯA verify trên GDS thật:
# phần WHERE ... IN $ids trước aggregation).
PROJECT_SUB_QUERY = """MATCH (s:Asset)-[r:CONNECTS_TO]->(t:Asset)
WHERE s.canonical_id IN $ids AND t.canonical_id IN $ids
WITH gds.graph.project($name, s, t, {relationshipProperties: r {.cost}}) AS g
RETURN g.nodeCount AS nodes, g.relationshipCount AS rels"""

# Dijkstra một cặp (trùng algo_demo.py DIJKSTRA, đã chạy thật GDS 2.13.13).
DIJKSTRA_QUERY = """MATCH (s:Asset {canonical_id: $src}), (t:Asset {canonical_id: $dst})
CALL gds.shortestPath.dijkstra.stream($name, {
  sourceNode: s, targetNodes: t, relationshipWeightProperty: 'cost'
})
YIELD totalCost, nodeIds
RETURN totalCost, [i IN nodeIds | gds.util.asNode(i).canonical_id] AS path"""

# BFS KHÔNG maxDepth: CHƯA verify trên GDS thật (algo_demo.py chỉ chạy bản có maxDepth).
BFS_QUERY = """MATCH (s:Asset {canonical_id: $src})
CALL gds.bfs.stream($name, {sourceNode: s})
YIELD nodeIds
RETURN [i IN nodeIds | gds.util.asNode(i).canonical_id] AS reached"""

# BFS có maxDepth: trùng algo_demo.py BFS (đã chạy thật).
BFS_DEPTH_QUERY = """MATCH (s:Asset {canonical_id: $src})
CALL gds.bfs.stream($name, {sourceNode: s, maxDepth: $max_depth})
YIELD nodeIds
RETURN [i IN nodeIds | gds.util.asNode(i).canonical_id] AS reached"""

# Betweenness: CHƯA verify trên GDS thật.
BETWEENNESS_QUERY = """CALL gds.betweenness.stream($name)
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).hostname AS hostname,
       gds.util.asNode(nodeId).canonical_id AS canonical_id, score"""


# ---------- I/O helper (driver tiêm từ ngoài) ----------
def _read(driver, query: str, **params) -> list[dict]:
    with driver.session() as session:
        return [rec.data() for rec in session.run(query, **params)]


def _drop_if_exists(driver, name: str) -> None:
    if _read(driver, GRAPH_EXISTS_QUERY, name=name)[0]["exists"]:
        _read(driver, GRAPH_DROP_QUERY, name=name)


def drop_projections(driver, names) -> None:
    """Drop các bản chiếu (nếu còn) — không để đồ thị trọng số nằm lại trong RAM."""
    for name in names:
        _drop_if_exists(driver, name)


def _project(driver, name: str, query: str, **params) -> dict | None:
    """Drop-nếu-tồn-tại rồi chiếu lại. Trả None nếu không có cạnh/node nào để chiếu."""
    _drop_if_exists(driver, name)
    rows = _read(driver, query, name=name, **params)
    if not rows or not rows[0].get("nodes"):
        return None
    return rows[0]


def _ensure_costs(driver) -> None:
    missing = _read(driver, MISSING_COST_QUERY)[0]["missing"]
    if missing:
        raise MissingCostError(
            f"{missing} cạnh CONNECTS_TO thiếu cost hoặc cost không hợp lệ (sai kiểu/âm) "
            "— chạy src/analysis/risk/risk_scoring.py trước khi tính attack path"
        )


def _projected_nodes(driver) -> set[str]:
    return {r["canonical_id"] for r in _read(driver, PROJECTED_NODES_QUERY)}


# ---------- Business context (chỉ đọc) ----------
def find_entry_points(driver) -> list[str]:
    """canonical_id của Asset có Service exposure='public' (đã gán bởi module risk)."""
    rows = _read(driver, ENTRY_POINTS_QUERY, exposure="public")
    return [r["canonical_id"] for r in rows]


def find_crown_jewels(driver, *, min_criticality: int = 4) -> list[str]:
    """canonical_id của Asset có asset_criticality >= min_criticality."""
    rows = _read(driver, CROWN_JEWELS_QUERY, min_criticality=min_criticality)
    return [r["canonical_id"] for r in rows]


# ---------- Thuật toán ----------
def rank_attack_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """Cost tăng dần (rẻ nhất = nguy hiểm nhất); hoà thì theo (source, target)."""
    return sorted(paths, key=lambda p: (p.total_cost, p.source, p.target))


def path_frequency(paths: list[AttackPath]) -> list[tuple[str, int]]:
    """Số attack path (đã tính theo cost) đi qua mỗi node, giảm dần (hoà: canonical_id).

    Tín hiệu choke point THEO cost, chỉ trên cặp entry->crown — BỔ SUNG cho betweenness
    của GDS (đếm theo số bước, mọi cặp), không thay thế. Mỗi path đếm một lần/node.
    """
    counter: Counter[str] = Counter()
    for p in paths:
        counter.update(set(p.hops))
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def shortest_attack_paths(
    driver,
    entries: list[str],
    crowns: list[str],
    *,
    graph_name: str = GRAPH_FULL,
) -> list[AttackPath]:
    """Dijkstra theo ``cost`` cho từng cặp (entry, crown).

    Yêu cầu risk_scoring.py đã ghi ``cost`` hợp lệ; sai -> ``MissingCostError``.
    Cặp mà một đầu không nằm trong bản chiếu (asset không có cạnh CONNECTS_TO) hoặc không
    có đường -> bỏ qua (GDS sẽ văng lỗi nếu truyền node ngoài graph). Entry TRÙNG crown
    (vừa public vừa critical — case nguy hiểm nhất) -> ``AttackPath(x, x, 0.0, [x])``.
    """
    if not entries or not crowns:
        return []
    _ensure_costs(driver)
    paths = [AttackPath(a, a, 0.0, [a]) for a in sorted(set(entries) & set(crowns))]
    if _project(driver, graph_name, PROJECT_FULL_QUERY) is None:
        return rank_attack_paths(paths)
    in_graph = _projected_nodes(driver)
    for src in sorted(set(entries) & in_graph):
        for dst in sorted(set(crowns) & in_graph):
            if src == dst:
                continue
            rows = _read(driver, DIJKSTRA_QUERY, name=graph_name, src=src, dst=dst)
            if not rows:
                continue
            paths.append(
                AttackPath(
                    source=src,
                    target=dst,
                    total_cost=float(rows[0]["totalCost"]),
                    hops=list(rows[0]["path"]),
                )
            )
    return rank_attack_paths(paths)


def reachable_from_entries(
    driver,
    entries: list[str],
    max_depth: int | None = None,
    *,
    graph_name: str = GRAPH_FULL,
) -> set[str]:
    """BFS reachability (ít bước, KHÔNG theo cost) từ các entry point.

    Entry nằm ngoài bản chiếu bị bỏ qua khi chạy BFS nhưng vẫn tính là reachable của
    chính nó.
    """
    if not entries:
        return set()
    reached: set[str] = set(entries)
    if _project(driver, graph_name, PROJECT_FULL_QUERY) is None:
        return reached
    in_graph = _projected_nodes(driver)
    for src in sorted(set(entries) & in_graph):
        if max_depth is None:
            rows = _read(driver, BFS_QUERY, name=graph_name, src=src)
        else:
            rows = _read(
                driver, BFS_DEPTH_QUERY, name=graph_name, src=src, max_depth=max_depth
            )
        for r in rows:
            reached.update(r["reached"])
    return reached


def choke_points(
    driver,
    *,
    subgraph_nodes: set[str] | None = None,
    graph_name: str = GRAPH_SUB,
) -> list[ChokePoint]:
    """Betweenness centrality (GDS) trên đồ thị con; xếp giảm dần.

    LƯU Ý NGỮ NGHĨA: ``gds.betweenness.stream`` chạy UNWEIGHTED (đếm số bước, bỏ qua
    ``cost``), trên MỌI cặp node của đồ thị con (không chỉ entry->crown), theo HƯỚNG cạnh
    (đúng cho luồng tấn công). Vì vậy nó có thể lệch với attack path xếp theo cost —
    dùng kèm ``path_frequency`` (đếm theo path Dijkstra thật). Procedure này CHƯA verify
    trên GDS thật.

    ``subgraph_nodes=None`` -> dùng toàn đồ thị Asset/CONNECTS_TO.
    """
    if subgraph_nodes is None:
        proj = _project(driver, graph_name, PROJECT_FULL_QUERY)
    else:
        if not subgraph_nodes:
            return []
        proj = _project(
            driver, graph_name, PROJECT_SUB_QUERY, ids=sorted(subgraph_nodes)
        )
    if proj is None:
        return []
    rows = _read(driver, BETWEENNESS_QUERY, name=graph_name)
    result = [
        ChokePoint(
            hostname=r["hostname"],
            canonical_id=r["canonical_id"],
            betweenness=float(r["score"]),
        )
        for r in rows
    ]
    result.sort(key=lambda c: (-c.betweenness, c.canonical_id))
    return result


# ---------- CLI ----------
def format_paths(paths: list[AttackPath], top: int = 10) -> str:
    lines = [f"{'#':>2} {'cost':>6}  {'entry':<14}{'crown':<14}đường đi"]
    for i, p in enumerate(paths[:top], 1):
        lines.append(
            f"{i:>2} {p.total_cost:>6.2f}  {p.source:<14}{p.target:<14}{' -> '.join(p.hops)}"
        )
    return "\n".join(lines)


def format_choke_points(points: list[ChokePoint], top: int = 10) -> str:
    lines = [f"{'#':>2} {'canonical_id':<14}{'hostname':<14}{'betweenness':>12}"]
    for i, c in enumerate(points[:top], 1):
        lines.append(
            f"{i:>2} {c.canonical_id:<14}{c.hostname:<14}{c.betweenness:>12.3f}"
        )
    return "\n".join(lines)


def format_frequency(freq: list[tuple[str, int]], top: int = 10) -> str:
    lines = [f"{'#':>2} {'canonical_id':<14}{'số path':>8}"]
    for i, (cid, n) in enumerate(freq[:top], 1):
        lines.append(f"{i:>2} {cid:<14}{n:>8}")
    return "\n".join(lines)


def run_attack_path(driver, *, min_criticality: int = 4):
    """entry/crown -> Dijkstra -> betweenness + path_frequency + BFS reachable.

    Trả ``(paths, chokes, freq, reachable)``. Bản chiếu GDS (tên có hậu tố ngẫu nhiên)
    luôn được drop ở cuối, kể cả khi lỗi.
    """
    suffix = uuid.uuid4().hex[:8]
    full, sub = f"{GRAPH_FULL}_{suffix}", f"{GRAPH_SUB}_{suffix}"
    try:
        entries = find_entry_points(driver)
        crowns = find_crown_jewels(driver, min_criticality=min_criticality)
        paths = shortest_attack_paths(driver, entries, crowns, graph_name=full)
        nodes = {h for p in paths for h in p.hops}
        chokes = (
            choke_points(driver, subgraph_nodes=nodes, graph_name=sub) if nodes else []
        )
        reachable = reachable_from_entries(driver, entries, graph_name=full)
        return paths, chokes, path_frequency(paths), reachable
    finally:
        drop_projections(driver, (full, sub))


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="Attack path (Dijkstra) + choke point (betweenness)"
    )
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--min-criticality", type=int, default=4)
    args = parser.parse_args(argv)

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    auth = (user, password) if password else None
    with GraphDatabase.driver(uri, auth=auth) as driver:
        try:
            paths, chokes, freq, reachable = run_attack_path(
                driver, min_criticality=args.min_criticality
            )
        except MissingCostError as exc:
            print(f"LỖI: {exc}", file=sys.stderr)
            return 1
    print("Đường tấn công (cost thấp = nguy hiểm):")
    print(format_paths(paths, args.top))
    print("\nChoke point (GDS betweenness — theo số bước, mọi cặp, có hướng):")
    print(format_choke_points(chokes, args.top))
    print("\nTần suất node trên attack path (theo cost):")
    print(format_frequency(freq, args.top))
    print(f"\nBFS: {len(reachable)} asset reachable từ entry point.")
    print(f"{len(paths)} đường tấn công.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
