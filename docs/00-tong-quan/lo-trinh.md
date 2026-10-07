# Lộ trình 8 tuần → thư mục code

| Giai đoạn | Tuần | Giờ | Module | Thư mục code |
|---|---|---|---|---|
| 01 — Đồ thị & mô hình dữ liệu | 1-2 | ~30h | Neo4j/Cypher, Mô hình hóa dữ liệu an ninh, Thuật toán đồ thị | `src/graph/`, `src/graph/algo/` |
| 02 — Nạp dữ liệu & tìm kiếm | 3-4 | ~30h | Các nguồn dữ liệu an ninh, Entity resolution, OpenSearch | `src/ingestion/`, `src/ingestion/resolution/`, `src/search/` |
| 03 — Lớp LLM trên đồ thị | 5-6 | ~30h | (RAG-from-scratch 10h còn nợ), Text2Cypher, GraphRAG, Eval | `src/llm/text2cypher/`, `src/llm/graphrag/`, `src/eval/` |
| 04 — Attack path & chấm điểm rủi ro | 7 | ~15h | Dự đoán đường tấn công, Chấm điểm rủi ro theo ngữ cảnh | `src/analysis/attack_path/`, `src/analysis/risk/` |
| 05 — Đóng gói & hồ sơ | 8 | ~15h | README, Docker compose, video demo, CV/GitHub, luyện phỏng vấn | (không phải code, xem gần cuối dự án) |
| 06 — Chạy song song | mỗi tuần ~5h | — | Đọc hiểu dữ liệu an ninh, SwarmSentinel, tìm hiểu VinSOC, ML cổ điển | Dự án SwarmSentinel riêng, không nằm trong repo này |

Tiến độ bài giảng (lý thuyết) chi tiết: theo dõi trong Claude Project `claude/tien-do-bai-giang.md`. Tính đến 2026-10-07: Giai đoạn 01-04 đã có bài giảng đầy đủ (11 module), Giai đoạn 05 chưa tới.

**Thứ tự code đề xuất**: bám đúng thứ tự lộ trình (01 → 02 → 03 → 04) vì mỗi giai đoạn sau phụ thuộc dữ liệu/schema giai đoạn trước (ví dụ Text2Cypher cần schema v2 đã nạp dữ liệu thật, risk scoring cần `HAS_VULN` đã nạp từ Giai đoạn 02).
