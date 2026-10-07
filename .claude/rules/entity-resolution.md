---
paths:
  - "src/ingestion/resolution/**"
---

# Entity resolution — quy tắc

Pipeline: blocking (giảm O(n×m), theo prefix hostname chuẩn hóa) → compare (exact + `rapidfuzz`: `fuzz.ratio` cho asset, biến thể tên + `fuzz.token_sort_ratio` cho username) → decision theo ngưỡng (`match`/`review`/`no_match`) → union-find gộp cụm → crosswalk (giữ mọi id gốc, không xóa).

**False merge nguy hiểm hơn false split** ở ngữ cảnh an ninh (xem `security.md`) — ngưỡng nên nghiêng an toàn, case biên vào `review_queue.json`, không tự merge/loại khi mơ hồ.

Xung đột field giữa nguồn: xử lý theo ưu tiên nguồn (nối nguyên tắc ở `graph-schema.md`).

Đánh giá bằng precision/recall/F1 trên tập nhãn tay, không chỉ nhìn qua.

Output: `resolved/crosswalk.json` (map mọi id gốc → `canonical_id`), `resolved/review_queue.json`. `canonical_id` là khóa MERGE khi nạp vào Neo4j.

Script: `entity_resolution.py`.

Chi tiết: `docs/giai-doan-02-data-pipeline/entity-resolution.md`.
