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
- **Chưa chạy thử trên Neo4j thật** — quantified relationship `{0,3}` và `SHORTEST 1` chưa xác minh trên bản đang dùng
- Thứ tự mục trong bài lệch so với khóa GraphAcademy (constraint/nạp dữ liệu đứng trước đọc/ghi)

Script: `seed_graph.py` (schema v1, chạy lặp được).
