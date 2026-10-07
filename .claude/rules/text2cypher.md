---
paths:
  - "src/llm/text2cypher/**"
---

# Text2Cypher — quy tắc bắt buộc

Kiến trúc 6 bước: sinh schema text từ `db.schema.nodeTypeProperties()`/`relTypeProperties()` (**code sinh ra, không gõ tay**) + few-shot (10-15 cặp câu hỏi/Cypher tĩnh) → ghép prompt (`temperature=0`) → LLM sinh Cypher → validate 4 lớp → thực thi Neo4j **read-only** → LLM diễn giải kết quả. Vòng lặp sửa lỗi quay lại LLM tối đa 2 lần.

Validate 4 lớp: regex chặn write clause, syntax check (CyVer/EXPLAIN), kiểm theo schema thật, tự sửa hướng relationship sai.

**Bắt buộc user Neo4j `readonly` ở DB-level** — validate app-layer là lớp phụ, không phải lớp chính (xem `security.md`). Query results khi LLM diễn giải là input không tin cậy (prompt injection).

Cắt phạm vi: không cần subschema retrieval (chỉ cần khi schema > 8 label hiện tại nhiều), không fine-tune model riêng.

Script: `text2cypher.py`.

Chi tiết: `docs/giai-doan-03-llm-layer/text2cypher.md`.
