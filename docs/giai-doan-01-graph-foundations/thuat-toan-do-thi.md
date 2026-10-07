# Thuật toán đồ thị an ninh

Bài giảng gốc: https://claude.ai/artifact/69ULPaDJuJUgMy11br83V3

## Quyết định chính
- GDS khi cần thuật toán sẵn (BFS/DFS, Dijkstra, PageRank, Louvain/Leiden), không tự cài
- Hai bẫy ngữ nghĩa: trọng số là chi phí hay độ gắn kết; hướng cạnh quyết định ý nghĩa PageRank
- Chiếu bằng Cypher aggregation (`gds.graph.project`); bản chiếu là bản chụp, đổi dữ liệu phải chiếu lại
- GDS 2.13.x qua docker-compose (`NEO4J_PLUGINS`)
- Dữ liệu bài: 3 máy lab thêm (vpn-01, jump-01, file-01), cost 1-10 trên `CONNECTS_TO` — **số minh họa, được tính lại thật ở module Chấm điểm rủi ro**

## Cắt
Tự cài thuật toán, node embedding/GNN/link prediction, các thuật toán GDS khác (A*, Yen, similarity — Yen tiếp tục cắt ở Giai đoạn 04), tinh chỉnh GDS quy mô triệu node, DFS (BFS đủ).

## Đã chạy thật (2026-10-07)
`src/graph/algo/algo_demo.py` chạy trên Neo4j 5.26 Community + **GDS 2.13.13** (Docker, no-auth) + driver `neo4j` 6.4.0 — **tất cả 8 mục bảng 6.1 OK**, idempotent (seed MERGE/SET, bản chiếu drop rồi project lại).

- Chiếu `attack` (có hướng, có `cost`): **8 node / 10 cạnh**. `attack_u` (vô hướng): 8 node / 20 cạnh (mỗi cạnh đếm 2 chiều — đúng như ghi chú mục 4.3, không dùng làm tiêu chí).
- BFS web-01 depth 3: thăm {jump-01, app-01, file-01, db-01, dc-01} (không chạm vpn-01/ws-hr-01).
- Dijkstra web-01→db-01: **cost 4** qua `jump-01, file-01`; vs `shortestPath` ra `web-01→app-01→db-01` (2 bước) — hai đáp án khác nhau có chủ ý.
- Dijkstra vpn-01→dc-01 = 6; web-01→dc-01 = 8 (qua jump-01, file-01).
- PageRank (không trọng số): db-01 0.573 > dc-01 0.405 > file-01 0.386 > app-01 0.305 > jump-01 0.278 > ws-hr-01 0.214 > web-01 = vpn-01 = 0.15. **Khớp số tính tay trong bài giảng.**
- Louvain/Leiden: đều ra 3 cụm trên 8 node; ranh giới khác nhau giữa 2 thuật toán (và phụ thuộc seed) — chỉ dùng như gợi ý phân đoạn, không khẳng định cụm cụ thể.

GDS API đối chiếu tài liệu Neo4j: `gds.graph.project` (aggregation), `gds.graph.exists/drop`, `gds.bfs.stream`, `gds.shortestPath.dijkstra.stream`, `gds.pageRank.stream`, `gds.louvain.stream`, `gds.leiden.stream` (`randomSeed`).

## Còn nợ (chuyển Giai đoạn 04)
- **Betweenness centrality** (choke point) + `attack_path.py`: bài giảng module này không dạy, để dành Giai đoạn 04 cùng cạnh dẫn xuất từ quyền tài khoản.
- `cost` hiện là số minh họa gán tay — Giai đoạn 04 tính lại từ CVSS/EPSS/KEV (xem `attack-risk.md`).
- Ranh giới cụm Louvain/Leiden trên 8 node phụ thuộc seed, không kiểm cụ thể (đồ thị quá nhỏ để diễn giải là phát hiện thật).
