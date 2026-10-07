# Các nguồn dữ liệu an ninh

Bài giảng gốc: https://claude.ai/artifact/LjpvA9ePU3BBtEztaj4vys

## Kiến trúc
6 nguồn thô → 6 parser tay → tầng chuẩn hóa chung → (Entity resolution) → loader Neo4j (Giai đoạn 01).

Chi tiết endpoint/field: xem `../../.claude/rules/data-sources.md`.

## Quyết định chính
- Parser tay đúng ở quy mô demo (so với ETL framework/connector SIEM-VM trả phí)
- Schema-on-read + nắn về schema chung, pipeline idempotent, cache response, backoff 429
- Dữ liệu định danh giả lập bằng Python (không có AD thật), ghi rõ lệnh PowerShell tương đương

## Cắt
Parse EVTX nhị phân (`python-evtx`), ETL framework (Airbyte/Singer/Dagster), export AD thật qua PowerShell (chỉ ghi lệnh, không thực hành).

## Còn nợ khi code thật
- Hợp nhất record trùng giữa nguồn → Entity resolution
- Nạp log vào OpenSearch → module OpenSearch
- Nối `normalized/*.json` vào loader Neo4j (`model_v2.py`) — bài dừng ở xuất JSON
- **Chưa gọi được NVD/EPSS/KEV API thật** trong sandbox viết bài (không có mạng ra ngoài) — chỉ parser Nmap đã chạy thật trên XML mẫu tự tạo
- Dữ liệu định danh giả không có biến thể tên (cố ý, để làm bài toán cho Entity resolution)

Script: `sources.py` (xuất 6 file JSON vào `normalized/`).
