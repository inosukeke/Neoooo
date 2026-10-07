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
