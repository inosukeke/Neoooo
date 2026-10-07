# Text2Cypher cho đồ thị an ninh

Bài giảng gốc: https://claude.ai/artifact/MHPua3k8oBfR6dmAz4QAmv

Chi tiết quy tắc: `../../.claude/rules/text2cypher.md`.

## Quyết định chính
- So sánh 3 lựa chọn thư viện: `neo4j-graphrag` Text2CypherRetriever / LangChain GraphCypherQAChain / Neo4j MCP Server
- Schema text sinh bằng code từ `db.schema.*`, không gõ tay; few-shot 10-15 cặp tĩnh (retrieval theo similarity chỉ cần khi >30-40 cặp)
- Validate 4 lớp + vòng lặp sửa lỗi tối đa 2 lần

## Cắt
Subschema retrieval (vector/n-hop — chỉ cần khi schema lớn hơn nhiều), fine-tune model riêng, đo lường đầy đủ (để bài Eval).

## Còn nợ khi code thật
- **Chưa chạy thử trên Neo4j thật** — regex/retry mới kiểm logic tay
- Chưa tạo user Neo4j `readonly` thật
- `SCHEMA_TEXT` trong bài là bản rút gọn minh họa, chưa phải chuỗi sinh thật từ dữ liệu của Chinh
- Giả định `seed_graph.py`/`model_v2.py` đã chạy

Script: `text2cypher.py`.
