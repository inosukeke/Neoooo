# Các nguồn dữ liệu an ninh

Bài giảng gốc: https://claude.ai/artifact/LjpvA9ePU3BBtEztaj4vys

## Kiến trúc
6 nguồn thô → 6 parser tay → tầng chuẩn hóa chung → (Entity resolution) → loader Neo4j (Giai đoạn 01).

Chi tiết endpoint/field: xem `../../.claude/rules/data-sources.md`.

## Quyết định chính
- Parser tay đúng ở quy mô demo (so với ETL framework/connector SIEM-VM trả phí)
- Schema-on-read + nắn về schema chung, pipeline idempotent, cache response, backoff 429
- Dữ liệu định danh giả lập bằng Python (không có AD thật), ghi rõ lệnh PowerShell tương đương
- **Quy mô dữ liệu giả lập mục tiêu** (để đồ thị cuối ra ~50-150 node, xem `../00-tong-quan/chien-luoc.md` § Quy mô mục tiêu): ~15-30 Asset (Nmap), ~20-40 CVE map qua NVD/EPSS/KEV, ~15-20 User/Account, vài chục Alert/log mẫu — đủ tạo nhiều attack path cạnh tranh nhau và ít nhất 1-2 choke point rõ, không phải vài host như schema v1/v2 học khái niệm

## Cắt
Parse EVTX nhị phân (`python-evtx`), ETL framework (Airbyte/Singer/Dagster), export AD thật qua PowerShell (chỉ ghi lệnh, không thực hành).

## Đã chạy thật (2026-10-08, cập nhật: normalized đa-nguồn)
`src/ingestion/sources.py` + `gen_fixtures.py` đã chạy thật trên máy có mạng (Python 3, `requests` 2.32.3) — **gọi API công khai NVD/EPSS/KEV thật, thành công**:
- Xuất **7 file** `normalized/*.json`, mỗi record mang field **`source`** (pipeline tự mô tả nguồn). Asset/User **đa-nguồn** để Entity resolution có việc gộp: **55 asset** (nmap 21 + ad 21 + log 13), **31 user** (idp 16 + hr 15), 33 service, **28 vulnerability**, 16 account, 21 membership, 30 alert.
- AD (góc nhìn máy, tên biến thể) và HR (góc nhìn user) là **nguồn thật trong tầng ingestion** — `gen_fixtures.py` sinh `data/sample_ad.json` + `sample_hr.json` + `data/er_truth.json` (nhãn eval), `sources.py` chuẩn hóa chúng vào `normalized/` cùng Nmap/IdP/Log. ER (module 2) chỉ đọc `normalized/`, không tự chế data.
- **Completeness: 28/28 CVE đủ cả 3 nguồn** (NVD cvss + EPSS + KEV). CVE-2021-44228: CVSS 10.0 CRITICAL, EPSS 0.99999, KEV ransomware=true.
- Cache 57 file (`cache/`, đã commit) → chạy lần 2 **2s, offline, output y hệt** (idempotent: identity theo seed, API đọc cache).
- `gen_fixtures.py` sinh `data/sample_nmap.xml` (22 host, 21 up, 33 port mở — có host down/port đóng để test lọc) + `sample_logs.jsonl` (30 logon 4624/4625, tham chiếu host Nmap + user seed=42).

Quyết định khi code (khác gợi ý "lab Docker thật" của bài giảng, chọn vì tái lập được): Nmap + log dùng dữ liệu mẫu sinh tất định & commit, không dựng lab/quét thật; CVE seed 28 cái nổi tiếng (toàn bộ nằm trong KEV). API thật nhưng cache commit nên demo chạy offline.

## Còn nợ (module/giai đoạn sau)
- Hợp nhất record trùng giữa nguồn → Entity resolution (module 2)
- Nạp log/alert vào OpenSearch → module OpenSearch (module 3)
- Nối `normalized/*.json` vào loader Neo4j + map CVE→service (CPE/thủ công) → sau Entity resolution
- Dữ liệu định danh giả không có biến thể tên (cố ý, để làm bài toán cho Entity resolution)

Script: `sources.py` (parser + API, chuẩn hóa mọi nguồn → 7 file `normalized/`), `gen_fixtures.py` (sinh toàn bộ dữ liệu nguồn giả vào `data/`: Nmap XML, log, AD view, HR view, + `er_truth.json`).
