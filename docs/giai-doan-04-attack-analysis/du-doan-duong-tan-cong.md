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
- **Chưa chạy thử trên Neo4j/GDS thật**. Chiếu đồ thị dùng `gds.graph.project` (Cypher aggregation, như `algo_demo.py` — KHÔNG phải `gds.graph.project.cypher`). Project/Dijkstra/BFS-có-maxDepth trùng cú pháp đã chạy thật ở `algo_demo.py`; CHƯA xác nhận: `gds.betweenness.stream`, project đồ thị con (`WHERE ... IN $ids`), `gds.bfs.stream` không maxDepth
- Giả định `risk_scoring.py` đã chạy: `CONNECTS_TO.cost` hợp lệ (số, >= 0), `exposure`, `asset_criticality`. Thiếu/sai → `MissingCostError`, không tự bịa cost

## Quyết định triển khai (attack_path.py)
- **Betweenness có hướng, unweighted, mọi cặp** của đồ thị con: `gds.betweenness.stream` đếm theo số bước, bỏ qua `cost`, không giới hạn cặp entry→crown, nên có thể lệch với đường xếp theo cost (Dijkstra). Giữ có hướng vì luồng tấn công có hướng.
- **Bổ sung `path_frequency(paths)`**: đếm số attack path (theo cost, chỉ cặp entry→crown) đi qua mỗi node — tín hiệu choke point nhất quán với cost; dùng cạnh betweenness, không thay thế. `run_attack_path` trả `(paths, chokes, freq, reachable)`.
- Entry/crown không nằm trong bản chiếu (asset không có cạnh `CONNECTS_TO`) bị lọc trước khi gọi GDS (tránh lỗi node ngoài graph) → coi như không có đường.
- Entry trùng crown (vừa public vừa critical) → `AttackPath(x, x, 0.0, [x])`, đứng đầu bảng.
- Bản chiếu GDS có hậu tố ngẫu nhiên, drop ở cuối (kể cả khi lỗi) vì đồ thị cost là tài liệu nhạy cảm.

Script: `attack_path.py`.
