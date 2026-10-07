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

## Còn nợ khi code thật
- **Chưa chạy thử trên Neo4j/GDS thật** — kết quả mong đợi tính tay + kiểm bằng NetworkX, chưa đối chiếu tài liệu DFS/exists/drop/seed Louvain/allowlist `gds.*`
- Ranh giới cụm Louvain/Leiden trên 8 node phụ thuộc seed, không kiểm cụ thể

Script: `algo_demo.py`. Kỳ vọng: chiếu `attack` ra 8 node/10 cạnh; Dijkstra web-01→db-01 cost 4 qua jump-01, file-01; PageRank: db-01 cao nhất.
