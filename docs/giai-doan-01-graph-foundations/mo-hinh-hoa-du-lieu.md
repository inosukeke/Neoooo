# Mô hình hóa dữ liệu an ninh (schema v2)

Bài giảng gốc: https://claude.ai/artifact/XU6abPcPqeTkn5YNXF16zd

## Quyết định chính
- Mô hình sinh ra từ câu hỏi, không từ dữ liệu (quy trình 4 bước: miền dữ liệu → câu hỏi → dựng mô hình → kiểm bằng câu hỏi)
- Relationship: type cụ thể, có hướng, không thêm cạnh ngược dư; intermediate node khi cần (ví dụ Finding)
- Schema v2 thêm `Group`, `Alert`; thêm `MEMBER_OF`, `ADMIN_TO`, `AUTHENTICATED_TO`, `OWNS`, `TRIGGERED_ON`, `INVOLVES`; split `CAN_ACCESS` và `ADMIN_TO`; property `first_seen`/`status` trên `HAS_VULN`
- Tách "có thể làm" (`CAN_ACCESS`, `ADMIN_TO`) khỏi "đã quan sát" (`AUTHENTICATED_TO`)
- Mô hình hóa thời gian: trạng thái dùng property, sự kiện dùng `datetime` + index; chưa cần timeline tree ở quy mô demo
- Tham chiếu schema BloodHound (node/cạnh theo quyền cụ thể, traversable/non-traversable, HasSession) — không copy, chỉ đối chiếu

## Cắt
STIX/OCSF/ontology-RDF, cạnh Azure/Entra + ACL BloodHound chi tiết, versioning toàn đồ thị, entity resolution (module riêng).

## Còn nợ khi code thật
- Map dữ liệu thật (Nmap, NVD, EPSS, KEV, AD) vào schema v2 — thuộc module Các nguồn dữ liệu an ninh
- Một máy nhiều tên/IP để dành cho Entity resolution (cố ý chưa resolve ở đây)

## Đã chạy thật — xác nhận 2026-10-07
Chạy trên Neo4j Kernel **5.26.31 Community** (Docker) + driver Python `neo4j` **6.4.0**, qua `src/graph/model_v2.py` (sau khi đã chạy `seed_graph.py`).

- **`EXISTS { ... }` subquery** (câu hỏi 3 và 4): chạy được, không lỗi cú pháp.
- **Quantified relationship `*0..1`** (câu hỏi 2, `MEMBER_OF*0..1`): chạy được.
- **`FOREACH` với `CASE WHEN c IS NULL THEN [] ELSE [1] END`** (nạp Alert, account có thể null): chạy được, đúng tạo `INVOLVES` có điều kiện.
- **`datetime(...)`** (literal và so sánh khoảng): chạy được, lọc alert theo ngày đúng kết quả.
- Cả 8 câu hỏi kiểm ra đúng 100% kết quả mong đợi ở mục 6.1, kể cả câu 5a đổi từ 2→3 bước cho bob (đúng hiệu ứng "đổi mô hình đổi câu trả lời" bài giảng dự đoán khi quyền đi qua nhóm DBA).
- Số node/relationship khớp 100% mục 6.2: node tổng 28 (Account 4, Alert 3, Asset 5, Group 2, Network 3, Service 4, User 4, Vulnerability 3), relationship tổng 37.
- Chạy script lần hai: số liệu giữ nguyên, kể cả bước `DELETE` cạnh `CAN_ACCESS` cũ — xác nhận idempotent.

Script: `model_v2.py` (migration v1→v2, chạy 8 câu hỏi kiểm, đã test thật — xem `README.md`). Output kỳ vọng: node tổng 28, relationship tổng 37.

## Nạp từ pipeline Giai đoạn 02 (loader `src/graph/load_graph.py`)

Thay thế toàn bộ dữ liệu dạy khái niệm (`seed_graph.py`/`model_v2.py`/`algo_demo.py`) bằng dữ liệu pipeline thật (`src/ingestion/normalized/*.json` + `src/ingestion/resolved/crosswalk.json`). Khóa MERGE đổi từ `hostname`/`username` sang **`canonical_id`** (ổn định qua entity resolution, trong khi `hostname` có thể trùng giữa node cũ/mới).

**Node** (khóa MERGE in đậm):

| Label | Khóa | Property SET | Nguồn |
|---|---|---|---|
| Asset | **canonical_id** | hostname (UNIQUE, ưu tiên nmap > log > AD đã chuẩn hóa), ip (có thể null), role (suy từ tên host, giả định demo), sources, source_ids, in_review | normalized/assets.json + crosswalk + review_queue |
| Network | **cidr** | zone (giả định theo /24) | suy từ ip |
| Service | **id** = `asset_canonical_id:port/protocol` | port, protocol, name, product, version | normalized/services.json |
| Vulnerability | **cve** | cvss, cvss_severity, epss, epss_percentile, kev, kev_date_added, kev_due_date, kev_ransomware, description (untrusted) | normalized/vulnerabilities.json |
| User | **canonical_id** | username (UNIQUE, ưu tiên idp > HR đã chuẩn hóa), display_name, sources, source_ids | normalized/users.json + crosswalk |
| Account | **name** | account_type, enabled | normalized/accounts.json |
| Group | **name** | — | normalized/memberships.json |
| Alert | **id** (= `alert_id` tất định) | time, event_id, success, severity, rule | normalized/alerts.json (chỉ 30 bản gốc, không nạp log nhân bản dùng cho OpenSearch) |

**Cạnh:**
- `(Asset)-[:IN_NETWORK]->(Network)`, `(Asset)-[:RUNS]->(Service)-[:HAS_VULN {first_seen,status}]->(Vulnerability)`, `(User)-[:HAS_ACCOUNT]->(Account)-[:MEMBER_OF]->(Group)`.
- `(Group)-[:ADMIN_TO]->(Asset)` và CVE→Service: **suy diễn từ bảng rule viết tay** (`src/graph/graph_rules.py`, `ADMIN_RULES`/`CVE_SERVICE_RULES`) — không có dữ liệu nguồn thật cho 2 quan hệ này, ghi rõ là **giả định nghiệp vụ demo**.
- `(Asset)-[:CONNECTS_TO {ports,rules}]->(Asset)`: suy diễn từ `CONNECT_RULES` (role/zone/hostname + cổng mở thật của dịch vụ đích). **Không set `cost`** — để trống cho Giai đoạn 04 tính theo CVSS/EPSS/KEV (xem `attack-risk.md`).
- `(Account)-[:AUTHENTICATED_TO {last_seen}]->(Asset)`: chỉ từ alert 4624 (logon thành công).
- `(Alert)-[:TRIGGERED_ON]->(Asset)`, `(Alert)-[:INVOLVES]->(Account)`.
- **`OWNS` không nạp** — không có nguồn dữ liệu nào xác định "chủ máy" trong pipeline demo.

**Constraint mới**: `asset_canonical_id`, `user_canonical_id` (UNIQUE) thay cho constraint theo `hostname`/`username` thuần của schema v1/v2 ban đầu.

Lưu ý: loader dùng dữ liệu `--reset` để dọn toy graph Giai đoạn 01 trước khi nạp (tránh đụng constraint `hostname UNIQUE` cũ) — sau đó `seed_graph.py`/`model_v2.py`/`algo_demo.py` không còn phản ánh đúng dữ liệu trong DB (đúng thiết kế, các file này vẫn giữ nguyên làm tài liệu học, không xóa).

### Đã chạy thật (2026-10-08)
`src/graph/load_graph.py --reset` đã chạy thật trên Neo4j 5.26 Community (container `neo4j-sec`), xóa toy graph Giai đoạn 01 và nạp dữ liệu pipeline:
- **Node: 158** (Asset 26, Network 3, Service 33, Vulnerability 28, User 17, Account 16, Group 5, Alert 30) — khớp 100% kỳ vọng.
- **Relationship: 243** (IN_NETWORK 21, RUNS 33, HAS_VULN 16, HAS_ACCOUNT 16, MEMBER_OF 21, ADMIN_TO 16, CONNECTS_TO 38, AUTHENTICATED_TO 22, TRIGGERED_ON 30, INVOLVES 30) — khớp 100%.
- Chạy lại lần 2 không `--reset`: số liệu giữ nguyên (idempotent xác nhận).
- `SHOW CONSTRAINTS` có đủ `asset_canonical_id`/`user_canonical_id`. Không `CONNECTS_TO` nào có property `cost`. Có đường `CONNECTS_TO*1..3` nhiều bước giữa các Asset; đúng 10 Asset chạm được `Vulnerability{kev:true}` qua `RUNS→HAS_VULN`.
- Guard hoạt động đúng: không `--reset` mà DB có Asset/User thiếu `canonical_id` → script dừng (`exit 2`), không ghi gì.
