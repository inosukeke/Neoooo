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
- **Chưa chạy thử trên Neo4j thật** — EXISTS subquery, `*0..1`, FOREACH, datetime chưa xác minh
- Một máy nhiều tên/IP để dành cho Entity resolution (cố ý chưa resolve ở đây)

Script: `model_v2.py` (migration v1→v2, chạy 8 câu hỏi kiểm). Output kỳ vọng: node tổng 28, relationship tổng 37.
