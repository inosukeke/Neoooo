# Entity resolution cho đồ thị an ninh

Bài giảng gốc: https://claude.ai/artifact/SMLz2o66XbR87qhcj4y3Qo

Chi tiết quy tắc: `../../.claude/rules/entity-resolution.md`.

## Quyết định chính
- Fuzzy rule-based đúng ở quy mô demo (so với exact-key, ML có nhãn)
- Blocking theo prefix hostname chuẩn hóa; `rapidfuzz` (`fuzz.ratio`, `fuzz.token_sort_ratio`); union-find gộp cụm khi entity xuất hiện ≥3 nguồn
- Đánh giá bằng precision/recall/F1 trên tập nhãn tay; false merge nguy hiểm hơn false split

## Cắt
Weighted multi-field scoring đầy đủ, active learning/ML matching, blocking nâng cao (minhash/LSH — chỉ cần biết tồn tại).

## Còn nợ khi code thật
- Cần tự tạo biến thể tên giả (`make_ad_view`) vì dữ liệu định danh giả ở bài trước không có sẵn
- Chưa nối `crosswalk.json` vào loader Neo4j (dùng `canonical_id` làm khóa MERGE) — chưa viết code loader
- Đã chạy thật bằng dữ liệu mẫu tay (3 asset), chưa chạy trên `normalized/assets.json` thật
- Pipeline cho users/accounts (`match_username`) chỉ có code mẫu, chưa tự chạy

Script: `entity_resolution.py` → output `resolved/crosswalk.json`, `resolved/review_queue.json`.
