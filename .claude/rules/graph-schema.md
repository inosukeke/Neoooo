---
paths:
  - "src/graph/**"
  - "src/pipeline/**"
---

# Schema đồ thị (v2) — nguồn sự thật

Node: `User`, `Account`, `Asset`, `Service`, `Vulnerability`, `Network`, `Group`, `Alert`.

Relationship chính: `MEMBER_OF`, `ADMIN_TO`, `AUTHENTICATED_TO`, `OWNS`, `TRIGGERED_ON`, `INVOLVES`, `CAN_ACCESS`, `HAS_VULN` (property `first_seen`, `status`), `CONNECTS_TO` (property `cost` 1-10, ghi đè bởi risk scoring ở Giai đoạn 04).

Nguyên tắc tách relationship: `CAN_ACCESS`/`ADMIN_TO` ("có thể làm") tách khỏi `AUTHENTICATED_TO` ("đã quan sát") — ví dụ attack path qua phiên admin còn lưu trên máy bị chiếm là hai việc khác nhau.

Property business-context thêm ở Giai đoạn 04 (không suy ra được từ Nmap/CVE, phải gán tay): `exposure` trên `Service`, `asset_criticality` trên `Asset`.

**Quy tắc MERGE**: chỉ khai báo khóa định danh duy nhất trong `{}` của MERGE, mọi property khác dùng `SET`/`ON CREATE SET`. Không viết CREATE cho dữ liệu có thể nạp lại nhiều lần.

Constraint: uniqueness constraint (kèm range index) cho khóa định danh mỗi label — node key nhiều property chỉ có ở Neo4j Enterprise, không dùng ở Community.

Mô hình hóa thời gian: trạng thái dùng property hiện tại, sự kiện dùng `datetime` + index property thời gian; chưa cần timeline tree ở quy mô demo.

Không lưu bí mật vào property (xem `security.md`).

**Khóa MERGE sau khi nạp pipeline Giai đoạn 02**: `canonical_id` cho `Asset`/`User` (không dùng `hostname`/`username` thuần — có thể trùng giữa node cũ/mới qua entity resolution). `ADMIN_TO`, CVE→`Service` (map vào `HAS_VULN`) và `CONNECTS_TO` được **suy diễn từ bảng rule viết tay** (`src/graph/graph_rules.py`) vì pipeline demo không có nguồn dữ liệu thật cho 3 quan hệ này — luôn ghi rõ "giả định demo" khi đọc/sửa các rule đó. `OWNS` không nạp (không có nguồn).

Script liên quan: `seed_graph.py` (schema v1 ban đầu), `model_v2.py` (schema v2 hiện hành + 8 câu hỏi kiểm), `load_graph.py` (nạp dữ liệu pipeline Giai đoạn 02, thay thế dữ liệu dạy khái niệm ở trên).

Chi tiết đầy đủ + quyết định thiết kế: `docs/giai-doan-01-graph-foundations/mo-hinh-hoa-du-lieu.md`.
