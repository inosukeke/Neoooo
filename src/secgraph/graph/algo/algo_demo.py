"""Giai đoạn 01 — Thuật toán đồ thị (GDS): seed overlay lab + chạy/kiểm 5 thuật toán.

Thêm 3 máy lab (vpn-01, jump-01, file-01) và gán ``cost`` 1..10 (nhỏ = dễ đi) cho
10 cạnh CONNECTS_TO, chiếu 2 đồ thị vào RAM rồi chạy BFS, Dijkstra, PageRank,
Louvain, Leiden — đối chiếu với bảng kết quả mong đợi (mục 6.1 bài giảng).

Idempotent: seed dùng MERGE/SET; bản chiếu drop-nếu-tồn-tại rồi project lại (bản
chiếu là bản chụp, đổi dữ liệu phải chiếu lại). ``cost`` ở đây là số minh họa gán
tay — Giai đoạn 04 tính lại từ CVSS/EPSS/KEV (xem attack-risk.md).

Yêu cầu: Neo4j 5.26 + GDS 2.13.x (``RETURN gds.version()`` chạy được) và đã chạy
model_v2.py. Lưu ý: script đưa DB lên 8 Asset / 10 CONNECTS_TO, nên model_v2.py
chạy lại sau đó sẽ báo LỆCH số lượng (đúng thiết kế) — dùng query dọn ở cuối file
để quay lại dữ liệu bài trước nếu cần.
"""
import os
import sys

from neo4j import GraphDatabase

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
USER = os.getenv("NEO4J_USER", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD")
# Demo local: cho phép Neo4j không đặt mật khẩu (NEO4J_AUTH=none) — khi đó auth=None.
AUTH = (USER, PASSWORD) if PASSWORD else None

# 3 máy lab thêm cho bài thuật toán (đánh dấu lab_algo để dọn được).
LAB_ASSETS = [
    {"hostname": "vpn-01", "ip": "10.0.1.5", "role": "vpn", "criticality": 2, "net": "10.0.1.0/24"},
    {"hostname": "jump-01", "ip": "10.0.3.10", "role": "jump", "criticality": 3, "net": "10.0.3.0/24"},
    {"hostname": "file-01", "ip": "10.0.3.40", "role": "file", "criticality": 3, "net": "10.0.3.0/24"},
]

# cost 1..10, NHỎ = DỄ ĐI (máy đích có KEV / cấu hình lỏng), lớn = khó (được gia cố).
# Số minh họa gán tay (bài giảng mục 4.1), KHÔNG phải số đo — Giai đoạn 04 tính lại thật.
EDGES = [
    {"src": "web-01", "dst": "app-01", "cost": 2},
    {"src": "app-01", "dst": "db-01", "cost": 9},
    {"src": "ws-hr-01", "dst": "app-01", "cost": 2},
    {"src": "ws-hr-01", "dst": "dc-01", "cost": 4},
    {"src": "web-01", "dst": "jump-01", "cost": 1},
    {"src": "jump-01", "dst": "file-01", "cost": 1},
    {"src": "file-01", "dst": "db-01", "cost": 2},
    {"src": "vpn-01", "dst": "ws-hr-01", "cost": 2},
    {"src": "vpn-01", "dst": "jump-01", "cost": 3},
    {"src": "file-01", "dst": "dc-01", "cost": 6},
]

SEED_ASSETS = """
UNWIND $rows AS r
MERGE (n:Network {cidr: r.net})
MERGE (a:Asset {hostname: r.hostname})
  SET a.ip = r.ip, a.role = r.role, a.criticality = r.criticality, a.lab_algo = true
MERGE (a)-[:IN_NETWORK]->(n)
"""

SEED_EDGES = """
UNWIND $rows AS r
MATCH (s:Asset {hostname: r.src}), (t:Asset {hostname: r.dst})
MERGE (s)-[c:CONNECTS_TO]->(t)
  SET c.cost = r.cost
"""

# Bản có hướng, có trọng số: BFS, Dijkstra, PageRank.
PROJECT_DIRECTED = """
MATCH (s:Asset)-[r:CONNECTS_TO]->(t:Asset)
WITH gds.graph.project('attack', s, t, {relationshipProperties: r {.cost}}) AS g
RETURN g.nodeCount AS nodes, g.relationshipCount AS rels
"""

# Bản vô hướng: Louvain, Leiden (số cạnh có thể nhân đôi — không dùng làm tiêu chí đúng/sai).
PROJECT_UNDIRECTED = """
MATCH (s:Asset)-[r:CONNECTS_TO]->(t:Asset)
WITH gds.graph.project('attack_u', s, t, {}, {undirectedRelationshipTypes: ['*']}) AS g
RETURN g.nodeCount AS nodes, g.relationshipCount AS rels
"""

BFS = """
MATCH (s:Asset {hostname: $src})
CALL gds.bfs.stream('attack', {sourceNode: s, maxDepth: $depth})
YIELD nodeIds
RETURN [i IN nodeIds | gds.util.asNode(i).hostname] AS order
"""

DIJKSTRA = """
MATCH (s:Asset {hostname: $src}), (t:Asset {hostname: $dst})
CALL gds.shortestPath.dijkstra.stream('attack', {
  sourceNode: s, targetNodes: t, relationshipWeightProperty: 'cost'
})
YIELD totalCost, nodeIds
RETURN totalCost, [i IN nodeIds | gds.util.asNode(i).hostname] AS path
"""

HOP_PATH = """
MATCH (s:Asset {hostname: $src}), (t:Asset {hostname: $dst}),
      p = shortestPath((s)-[:CONNECTS_TO*]->(t))
RETURN [n IN nodes(p) | n.hostname] AS path, length(p) AS hops
"""

# PageRank/Louvain chạy KHÔNG trọng số: cost là chi phí (nhỏ=tốt), không phải độ gắn kết.
PAGERANK = """
CALL gds.pageRank.stream('attack', {maxIterations: 20, dampingFactor: 0.85})
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).hostname AS host, score
ORDER BY score DESC, host
"""

LOUVAIN = """
CALL gds.louvain.stream('attack_u')
YIELD nodeId, communityId
RETURN communityId, collect(gds.util.asNode(nodeId).hostname) AS hosts
ORDER BY communityId
"""

LEIDEN = """
CALL gds.leiden.stream('attack_u', {randomSeed: 42})
YIELD nodeId, communityId
RETURN communityId, collect(gds.util.asNode(nodeId).hostname) AS hosts
ORDER BY communityId
"""

failures = []


def check(name, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + name + (("  " + detail) if detail else ""))
    if not ok:
        failures.append(name)


def main():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print(f"Đã kết nối {URI}")

        def run(query, **params):
            return driver.execute_query(query, database_="neo4j", **params).records

        gds_rows = run("RETURN gds.version() AS v")
        print("GDS version:", gds_rows[0]["v"])

        # 1. Seed overlay (idempotent)
        run(SEED_ASSETS, rows=LAB_ASSETS)
        run(SEED_EDGES, rows=EDGES)

        # 2. Chiếu lại (drop nếu đã tồn tại — bản chiếu là bản chụp)
        for name in ("attack", "attack_u"):
            if run("CALL gds.graph.exists($n) YIELD exists RETURN exists", n=name)[0]["exists"]:
                run("CALL gds.graph.drop($n) YIELD graphName RETURN graphName", n=name)
        d = run(PROJECT_DIRECTED)[0]
        check("1  chiếu attack (8 node, 10 cạnh)", d["nodes"] == 8 and d["rels"] == 10,
              f"nodes={d['nodes']} rels={d['rels']}")
        u = run(PROJECT_UNDIRECTED)[0]
        check("1b chiếu attack_u (8 node)", u["nodes"] == 8, f"nodes={u['nodes']} rels={u['rels']}")

        # 3. BFS từ web-01, tối đa 3 bước
        order = run(BFS, src="web-01", depth=3)[0]["order"]
        print("   BFS thứ tự thăm:", order)
        check("2  BFS web-01 depth 3",
              set(order) - {"web-01"} == {"app-01", "jump-01", "db-01", "file-01", "dc-01"})

        # 4. Dijkstra (đường dễ nhất) so với shortestPath (ít bước nhất)
        def dijkstra(src, dst):
            r = run(DIJKSTRA, src=src, dst=dst)[0]
            return float(r["totalCost"]), r["path"]

        cost, path = dijkstra("web-01", "db-01")
        print("   Dijkstra web-01 → db-01:", cost, path)
        check("3  Dijkstra web-01 → db-01 (cost 4)",
              cost == 4.0 and path == ["web-01", "jump-01", "file-01", "db-01"])

        hop = run(HOP_PATH, src="web-01", dst="db-01")[0]
        print("   shortestPath web-01 → db-01:", hop["path"], f"({hop['hops']} bước)")
        check("4  shortestPath web-01 → db-01 (2 bước, khác #3)",
              hop["path"] == ["web-01", "app-01", "db-01"] and hop["hops"] == 2)

        cost, path = dijkstra("vpn-01", "dc-01")
        print("   Dijkstra vpn-01 → dc-01:", cost, path)
        check("5  Dijkstra vpn-01 → dc-01 (cost 6)",
              cost == 6.0 and path == ["vpn-01", "ws-hr-01", "dc-01"])

        cost, path = dijkstra("web-01", "dc-01")
        print("   Dijkstra web-01 → dc-01:", cost, path)
        check("6  Dijkstra web-01 → dc-01 (cost 8)",
              cost == 8.0 and path == ["web-01", "jump-01", "file-01", "dc-01"])

        # 5. PageRank (không trọng số, đi theo hướng cạnh)
        pr = run(PAGERANK)
        ranks = [(r["host"], round(r["score"], 3)) for r in pr]
        print("   PageRank:", ranks)
        check("7  PageRank: db-01 đầu, dc-01 nhì",
              ranks[0][0] == "db-01" and ranks[1][0] == "dc-01")
        check("7b PageRank: web-01 & vpn-01 cuối bảng",
              {ranks[-1][0], ranks[-2][0]} == {"web-01", "vpn-01"})

        # 6. Cụm (vô hướng) — không khẳng định ranh giới trên đồ thị 8 node
        for label, query in (("Louvain", LOUVAIN), ("Leiden", LEIDEN)):
            rows = run(query)
            for r in rows:
                print(f"   {label} cụm {r['communityId']}: {r['hosts']}")
            check(f"8  {label} có ≥ 2 cụm", len(rows) >= 2)

    print("\nTất cả OK." if not failures else "\nCó mục FAIL: " + ", ".join(failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

# --- Dọn để quay lại dữ liệu bài trước (chạy tay trong Neo4j Browser nếu cần) -------------
# MATCH (a:Asset) WHERE a.lab_algo = true DETACH DELETE a;
# MATCH (:Asset)-[c:CONNECTS_TO]->(:Asset) REMOVE c.cost;
# CALL gds.graph.drop('attack'); CALL gds.graph.drop('attack_u');
