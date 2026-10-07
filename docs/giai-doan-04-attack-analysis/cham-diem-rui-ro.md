# Chấm điểm rủi ro theo ngữ cảnh

Bài giảng gốc: https://claude.ai/artifact/B1RtT1c3M49jhHSR295TJt

Chi tiết công thức: `../../.claude/rules/attack-risk.md`.

## Quyết định chính
- Đối chiếu với SSVC/CISA BOD 26-04 thật (4 biến boolean → bậc hành động) — công thức tự thiết kế cho số liên tục để xếp hạng chi tiết, SSVC tránh tranh cãi trọng số nhưng không xếp hạng chi tiết được
- Dùng phép nhân (không cộng) để một nhân tử = 0 triệt tiêu được rủi ro
- Gộp PageRank với `asset_criticality` bằng `max()` — đóng khoản nợ "PageRank làm một phần điểm ưu tiên vá"

## Cắt
Tự implement SSVC decision tree đầy đủ, ML học trọng số từ dữ liệu lịch sử.

## Còn nợ khi code thật
- **Chưa chạy thử trên Neo4j thật** — công thức mới kiểm tay bằng số ví dụ (CVE-2021-44228 giả định → risk_score=1.0)
- EPSS refresh hàng ngày chỉ nêu nguyên tắc, chưa code tự động
- Sensitivity analysis chỉ có hướng dẫn, chưa có số liệu thật
- Giả định `HAS_VULN` đã nạp đúng và `exposure`/`asset_criticality` đã gán
- Bài cuối Giai đoạn 04. Tiếp theo: Giai đoạn 05 — Đóng gói, CV/GitHub, luyện phỏng vấn.

Script: `risk_scoring.py`.
