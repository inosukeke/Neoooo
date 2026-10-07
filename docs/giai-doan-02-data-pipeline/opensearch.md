# OpenSearch cho log an ninh

Bài giảng gốc: https://claude.ai/artifact/CSrLj9nJ3jWExEAsAbdCQg

Chi tiết quy tắc: `../../.claude/rules/opensearch.md`.

## Quyết định chính
- Dùng khi cần full-text/aggregation trên log; không cần khi dữ liệu nhỏ (file+grep đủ)
- Không có join tự động với Neo4j — nối tay bằng `asset_canonical_id`
- Cài Docker single-node (`DISABLE_SECURITY_PLUGIN=true` chỉ local dev); `opensearch-py` 3.x

## Cắt
Index Lifecycle Management đầy đủ, cụm nhiều node, snapshot/restore, `search_after`/scroll sâu, tối ưu cluster lớn.

## Còn nợ khi code thật
- **Chưa chạy thử trên OpenSearch thật** — chỉ kiểm cú pháp `opensearch-py` 3.2.0 bằng import/dựng client (không kết nối server)
- Log mẫu cần nhân bản (`expand_log_sample`) để aggregation có ý nghĩa
- Chưa viết script nối ngược kết quả OpenSearch vào truy vấn Neo4j (chỉ mô tả cách làm)
- Bài cuối Giai đoạn 02.

Script: `index_alerts.py`.
