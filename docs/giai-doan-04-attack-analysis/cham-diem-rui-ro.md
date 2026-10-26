# Chấm điểm rủi ro theo ngữ cảnh

Bài giảng gốc: https://claude.ai/artifact/B1RtT1c3M49jhHSR295TJt

Chi tiết công thức: `../../.claude/rules/attack-risk.md`.

## Quyết định chính
- Đối chiếu với SSVC/CISA BOD 26-04 thật (4 biến boolean → bậc hành động) — công thức tự thiết kế cho số liên tục để xếp hạng chi tiết, SSVC tránh tranh cãi trọng số nhưng không xếp hạng chi tiết được
- Dùng phép nhân (không cộng) để một nhân tử = 0 triệt tiêu được rủi ro
- Gộp PageRank với `asset_criticality` bằng `max()` — đóng khoản nợ "PageRank làm một phần điểm ưu tiên vá"

## Cắt
Tự implement SSVC decision tree đầy đủ, ML học trọng số từ dữ liệu lịch sử.

## Quy ước triển khai (`risk_scoring.py`)
- **Cost cạnh**: `cost(src→dst) = risk_to_cost(risk của node ĐÍCH)` — chi phí "bước vào" dst; dst rủi ro cao thì rẻ. Dst không có risk thì cost = 10.
- **Entry point đang dùng**: asset có ít nhất một `Service.exposure='public'`; reachable = BFS từ các entry point qua `CONNECTS_TO`. Định nghĩa này **lỏng hơn spec** ("public-facing + có lỗ hổng") vì không đòi entry point phải có vuln.
- **Risk của asset** = max risk các vuln `HAS_VULN` đang `open` (vuln thiếu cvss hoặc dữ liệu ngoài khoảng bị bỏ qua + log; `top_cve` chọn tất định theo cvss giảm dần rồi tên cve).
- **Business-context** (`exposure`, `asset_criticality`) điền từ bảng rule tay bằng `coalesce` — không đè giá trị đã gán tay. Bảng là **giả định nghiệp vụ demo**, không phải số đo.

## Hạn chế đã biết của công thức demo
- **Double-count criticality**: `asset_criticality` là nhân tử của risk, mà risk lại quyết định cost. Hệ quả: đường tới crown jewel luôn rẻ, và có thể **che toxic combination** ở node trung gian criticality thấp (risk node đó bị kéo xuống nên cạnh vào nó đắt, dù nó là mắt xích then chốt).

## Còn nợ khi code thật
- **PageRank chưa nối vào runner/CLI** (nợ có chủ đích): `run_risk_scoring(pagerank=...)` đã có hook nhưng mặc định 0.0 nên `patch_priority` hiện chỉ phản ánh `criticality/5`. GDS PageRank sẽ nối ở module Attack path.
- **Chưa chạy thử trên Neo4j thật** — công thức mới kiểm tay bằng số ví dụ (CVE-2021-44228 giả định → risk_score=1.0)
- EPSS refresh hàng ngày chỉ nêu nguyên tắc, chưa code tự động
- Sensitivity analysis chỉ có hướng dẫn, chưa có số liệu thật
- Giả định `HAS_VULN` đã nạp đúng và `exposure`/`asset_criticality` đã gán
- Bài cuối Giai đoạn 04. Tiếp theo: Giai đoạn 05 — Đóng gói, CV/GitHub, luyện phỏng vấn.

Script: `risk_scoring.py`.
