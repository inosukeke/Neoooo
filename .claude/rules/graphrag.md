---
paths:
  - "src/secgraph/llm/graphrag/**"
---

# GraphRAG — quy tắc

Khác Text2Cypher: không có LLM sinh Cypher. Kiến trúc: embed câu hỏi → vector index tìm node gốc → **Cypher mở rộng cố định** (không LLM sinh, giới hạn 1-2 hop để tránh supernode) → ghép ngữ cảnh (khử lặp khi top-k > 1) → LLM sinh câu trả lời.

Vector index tạo bằng `CREATE VECTOR INDEX` trên Neo4j; chỉ embed text mô tả (mô tả CVE, message Alert), **không embed cả node**.

Ngữ cảnh truy hồi là text thật từ dữ liệu → prompt injection rõ hơn Text2Cypher (xem `security.md`). Embedding cũng là dữ liệu nhạy cảm, cần access control.

Cắt phạm vi: không re-ranking, không multi-vector per entity, không agent tự chọn tool giữa Text2Cypher/GraphRAG (LangGraph) ở bước này.

Script: `graphrag_demo.py`.

Chi tiết: `docs/giai-doan-03-llm-layer/graphrag.md`.
