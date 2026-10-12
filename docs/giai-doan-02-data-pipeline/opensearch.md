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
- Bài cuối Giai đoạn 02.

## Đã chạy thật (2026-10-08)
`src/search/{os_client,index_alerts,search_alerts,join_neo4j}.py` chạy thật trên OpenSearch **2.17.1** (Docker, `DISABLE_SECURITY_PLUGIN=true`, bind 127.0.0.1) + `opensearch-py` 3.2.0:
- `index_alerts.py`: `expand_log_sample(factor=50, days=14, seed=42, burst=120)` nhân 30 alert gốc (qua `canonical.enrich_alert`) → **1620 doc** tất định, 30 doc `synthetic=false` + burst 120 doc 4625 trên asset nhận canonical_id `asset-014` (hostname `dc-01`, user `chi.tran1` — thành viên Domain Admins). Bulk index idempotent (`_id` = `alert_id`), mapping `computer`/`rule`/`message` kiểu `text`+sub-field `.keyword`.
- `search_alerts.py`: 4 query `bool` DSL — top asset bị logon thất bại (`asset-014`, doc_count **170**), `date_histogram` ra đúng **14** bucket, full-text `match "failed"` ra **470** hit (khớp đúng số doc event_id=4625), `term` trên `computer` (text) ra **0** hit vs `computer.keyword` ra **270** hit (minh chứng đúng rule text vs keyword).
- `join_neo4j.py`: nối tay qua `asset_canonical_id`, top asset bị logon thất bại ghép với CVE KEV từ Neo4j — `asset-014`/`dc-01` có `['CVE-2017-0144', 'CVE-2020-1472']` (khớp đúng rule `Windows SMB`/`Microsoft AD LDAP` trong `graph_rules.py`).
- Idempotent: chạy lại `index_alerts.py` không tăng số doc (cùng `_id`).

Script: `os_client.py` (client + mapping), `index_alerts.py` (nhân bản + bulk index), `search_alerts.py` (query mẫu), `join_neo4j.py` (nối Neo4j).
