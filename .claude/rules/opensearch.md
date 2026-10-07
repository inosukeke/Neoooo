---
paths:
  - "src/search/**"
---

# OpenSearch — quy tắc

Dùng cho log/alert cần full-text search + aggregation; Neo4j không có join tự động với OpenSearch — nối tay bằng `asset_canonical_id` (property gắn vào log sau entity resolution).

Mapping: chọn đúng field `text` (full-text, phân tích) vs `keyword` (exact match, aggregation) — `term` query trên field `text` cho kết quả khác/rỗng so với `keyword`.

Query DSL: dùng `bool` (must/filter/should/must_not), không build string nối (xem `security.md`). Bulk nạp qua `helpers.bulk` (`opensearch-py` 3.x).

`DISABLE_SECURITY_PLUGIN=true` **chỉ cho local dev**, không dùng ngoài demo cá nhân.

Khi nào dùng Neo4j, khi nào dùng OpenSearch: câu hỏi theo cấu trúc/quan hệ/đường đi → Neo4j; câu hỏi full-text/tần suất theo thời gian trên log → OpenSearch.

Script: `index_alerts.py`.

Chi tiết: `docs/giai-doan-02-data-pipeline/opensearch.md`.
