---
paths:
  - "src/secgraph/llm/text2cypher/**"
---

# Text2Cypher — quy tắc bắt buộc

Kiến trúc 6 bước: sinh schema text từ `db.schema.nodeTypeProperties()`/`relTypeProperties()` (**code sinh ra, không gõ tay**) + few-shot (10-15 cặp câu hỏi/Cypher tĩnh) → ghép prompt (`temperature=0`) → LLM sinh Cypher → validate 4 lớp → thực thi qua `session(default_access_mode="READ")` + `Query(cypher, timeout=...)`, cắt dòng ngay khi đọc (`itertools.islice`, không materialize hết) → LLM diễn giải kết quả. Vòng lặp sửa lỗi quay lại LLM tối đa 2 lần.

Validate 4 lớp: regex chặn write clause (sau khi coi string/comment/**backtick-quoted identifier** là vùng nguyên vẹn, không quét bên trong — bug tokenize backtick từng là blocker thật, đã fix), chặn `SHOW`, chặn `CALL <procedure>` bất kỳ (gồm tên trong backtick), syntax check (`EXPLAIN`), kiểm theo schema thật, tự sửa hướng relationship sai.

**Neo4j Community Edition không có RBAC** (không `CREATE ROLE`/`GRANT`) — xem `security.md`. Đã xác nhận thật (review): `session(default_access_mode="READ")` TRÊN THỰC TẾ server có chặn write clause thật (`Neo.ClientError.Statement.AccessMode`) trên instance đơn — là phòng thủ bổ sung có thật, dù Neo4j docs nói "no guarantee" (áp dụng cho ngữ cảnh cluster routing). **Nhưng KHÔNG chặn được procedure call** (`CALL gds.*`/`SHOW`/`dbms.*` — các procedure này có mode riêng, độc lập session mode) — nên validate app-layer 4 lớp (đặc biệt L1 chặn `CALL`/`SHOW`) vẫn là **lớp chính thực tế** cho nhóm tấn công này, risk-accepted, không phải lớp phụ như thiết kế lý tưởng ban đầu. Query results khi LLM diễn giải là input không tin cậy (prompt injection) — giá trị dữ liệu được escape `<`/`>` trước khi bọc tag, chống đóng tag sớm.

Cắt phạm vi: không cần subschema retrieval (chỉ cần khi schema > 8 label hiện tại nhiều), không fine-tune model riêng.

Script: `text2cypher.py`.

Chi tiết: `docs/giai-doan-03-llm-layer/text2cypher.md`.
