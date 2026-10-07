# Dự đoán đường tấn công

Bài giảng gốc: https://claude.ai/artifact/UnU4u6stJ6LD9qKhFPEFzn

Chi tiết quy tắc: `../../.claude/rules/attack-risk.md`.

## Quyết định chính
- Entry point/crown jewel là business context, gán tay (`exposure`, `asset_criticality`)
- Toxic combination: nhiều vấn đề rủi ro thấp nối thành chuỗi impact cao
- Betweenness centrality = choke point (khái niệm mới so với bài Thuật toán đồ thị)
- Kiến trúc: xác định entry/crown jewel → BFS/Dijkstra từng cặp → betweenness trên đồ thị con → xếp hạng → Neo4j Browser đủ để trực quan hóa (không cần UI riêng)

## Cắt
Yen's k-shortest-paths, toxic combination tự động hóa đầy đủ kiểu BloodHound, UI trực quan hóa riêng (vis.js/d3 — chỉ là lựa chọn).

## Còn nợ khi code thật
- Property `exposure`/`asset_criticality` chưa thật sự thêm vào dữ liệu lab — cần `SET` trước khi script chạy
- **Chưa chạy thử trên Neo4j/GDS thật** — `gds.graph.project.cypher`/`gds.betweenness.stream` theo tài liệu hiện hành, chưa xác nhận
- Giả định `algo_demo.py` đã chạy, cost `CONNECTS_TO` 1-10 có sẵn

Script: `attack_path.py`.
