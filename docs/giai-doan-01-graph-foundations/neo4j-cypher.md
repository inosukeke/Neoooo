# Neo4j và Cypher

Bài giảng gốc: https://claude.ai/artifact/L4HicwyEDrN9mV7mh8GyUB

## Đã cover
- So sánh Neo4j / PostgreSQL / OpenSearch / NetworkX, khi nào không dùng đồ thị
- Property graph: node, label, relationship, property; Cypher = vẽ pattern
- Dựng Neo4j 5.26 Community bằng Docker (bind 127.0.0.1), Browser (7474), Bolt (7687)
- Schema bài học v1: User, Account, Asset, Service, Vulnerability, Network; nạp mẫu bằng UNWIND + MERGE
- Đọc: MATCH, WHERE, OPTIONAL MATCH, count/collect. Ghi: CREATE vs MERGE, SET, ON CREATE SET, DETACH DELETE
- Đường đi nhiều bước `[:A|B*1..N]`, quantified relationship (5.9+), shortestPath/SHORTEST
- Uniqueness constraint (+ range index), PROFILE
- Python driver `neo4j` 6.x: execute_query, parameter, tránh Cypher injection

## Cắt
APOC/GDS (để module Thuật toán đồ thị), clustering/Fabric/Aura/Bloom, Cypher 25-only features, LOAD CSV.

## Còn nợ khi code thật
- GraphAcademy (Fundamentals, Cypher Fundamentals, Graph Data Modeling) chưa làm
- Thứ tự mục trong bài lệch so với khóa GraphAcademy (constraint/nạp dữ liệu đứng trước đọc/ghi)

## Đã chạy thật — xác nhận 2026-10-07
Chạy trên Neo4j Kernel **5.26.31 Community** (Docker, image `neo4j:5.26-community`) + driver Python `neo4j` **6.4.0**, qua `src/graph/seed_graph.py`.

- **Quantified relationship `-[:CONNECTS_TO]->{0,3}`**: chạy được, không cần fallback. Kết quả đúng như bài dự đoán: bob→db-01, alice→web-01, carol→ws-hr-01.
- **`SHORTEST 1 (a)-[:CONNECTS_TO]->+(b)`**: chạy được, không cần fallback về `shortestPath()`. Kết quả `["web-01","app-01","db-01"]`, khớp `shortestPath()` cũ.
- Số node/relationship sau khi nạp khớp 100% bảng ở mục 6 (Asset 5, Service 4, Vulnerability 3, User 3, Account 3, Network 3; tổng relationship 22).
- Chạy script lần hai: số liệu giữ nguyên — xác nhận idempotent.
- `PROFILE MATCH (a:Asset {hostname:'db-01'}) RETURN a` → plan có `NodeUniqueIndexSeek`, không có `NodeByLabelScan`.

Script: `seed_graph.py` (schema v1, chạy lặp được, đã test thật — xem `README.md`).
