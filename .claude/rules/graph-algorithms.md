---
paths:
  - "src/secgraph/graph/algo/**"
  - "src/secgraph/analysis/**"
---

# Thuật toán đồ thị — quy tắc dùng

Dùng Neo4j GDS (không tự cài thuật toán) khi cần: BFS (reachability, ít bước nhất), Dijkstra có trọng số (chi phí thấp nhất — khác BFS/`shortestPath` của Cypher thuần, có thể ra đường khác nhau), PageRank (ảnh hưởng/tầm quan trọng node, hướng cạnh quyết định ý nghĩa), Louvain/Leiden (community), betweenness centrality (choke point — asset nằm trên nhiều shortest path cùng lúc).

Quy trình GDS: chiếu đồ thị vào RAM bằng `gds.graph.project` (Cypher aggregation, có hướng/vô hướng) → chạy thuật toán → stream/write kết quả. **Bản chiếu là bản chụp** — đổi dữ liệu phải chiếu lại (`gds.graph.drop` rồi project lại).

`cost` trên `CONNECTS_TO` không phải hằng số gán tay — ở Giai đoạn 04 được tính từ `risk_score` thật (CVSS × EPSS/KEV × asset criticality × reachability). Xem `attack-risk.md`.

Cắt phạm vi: không tự implement BFS/Dijkstra/PageRank, không cần GNN/embedding/link prediction, không cần Yen's k-shortest-paths (chỉ cần 1 đường rẻ nhất).

Script: `algo_demo.py`, `attack_path.py`.

Chi tiết: `docs/giai-doan-01-graph-foundations/thuat-toan-do-thi.md`, `docs/giai-doan-04-attack-analysis/`.
