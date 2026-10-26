# GraphRAG cho đồ thị an ninh

Bài giảng gốc: https://claude.ai/artifact/UTqWFbomcTtpQ4B5QFyTBs

Chi tiết quy tắc: `../../.claude/rules/graphrag.md`.

## Quyết định chính
- VectorCypherRetriever vs HybridCypherRetriever (theo định nghĩa GraphRAG của Neo4j)
- Embed text mô tả (CVE, Alert), không embed cả node; mở rộng Cypher cố định 1-2 hop (tránh supernode)

## Lưu ý quan trọng
**Module RAG-from-scratch 10h của kế hoạch gốc (chèn trước Giai đoạn 03) chưa được giảng riêng** — bài này chỉ gói lý thuyết RAG tối thiểu đủ để build GraphRAG, không có phần thí nghiệm chunk size/phá retrieval/hybrid search đúng nghĩa. Nên tự làm thêm trước khi vào bài Eval.

## Phạm vi index hiện tại
Hiện **chỉ index `Vulnerability.description`** (property vector `embedding`, index `vuln_description_embedding`). Alert **không** được index vì node `Alert` trong graph không có property message (chỉ có `time`/`event_id`/`success`/`severity`/`rule`); message gốc nằm ở OpenSearch, không nằm trong Neo4j. Muốn GraphRAG trên Alert phải nạp message vào graph (hoặc embed ở OpenSearch) — ngoài phạm vi bước này.

## Cắt
Thí nghiệm chunk size/hybrid search đúng nghĩa (→ RAG-from-scratch còn nợ), re-ranking/multi-vector, agent tự chọn tool (LangGraph).

## Còn nợ khi code thật
- **Chưa chạy thử** `CREATE VECTOR INDEX`/`db.index.vector.queryNodes` trên Neo4j thật — tên hàm có thể lệch giữa bản 5.x
- Chưa thử embedding model trên câu tiếng Việt kỹ thuật an ninh thật
- Giả định dữ liệu CVE/Alert đã nạp từ Giai đoạn 02

Script: `graphrag_demo.py`.
