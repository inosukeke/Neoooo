---
paths:
  - "src/secgraph/eval/**"
---

# Eval cho lớp LLM — quy tắc

Golden set 40-50 câu, phân bố: 20 structured, 15 fuzzy, 5-10 adversarial (thử vượt ràng buộc read-only/prompt injection — tách riêng, không trộn vào accuracy chính).

Metric Text2Cypher: **execution accuracy** (đáng tin hơn exact match). Metric GraphRAG: tách retrieval (contextual precision/recall/relevancy) và generation (answer relevancy, faithfulness) qua `deepeval` — tách để biết sửa ở đâu.

Bắt buộc đo **chi phí ($/câu hỏi) và độ trễ (p50/p95)**, không chỉ độ chính xác — bắt buộc cho demo.

Nếu dùng LLM-as-judge: tự chấm tay 10 câu, đo % đồng thuận trước khi tin số judge.

Phân loại mọi câu sai theo đúng một nguyên nhân cụ thể, không chỉ ghi đúng/sai.

`deepeval` API cập nhật thường xuyên — `pip show deepeval` và đọc docstring trước khi tin cú pháp class/tham số.

Script: `eval_harness.py`.

Chi tiết: `docs/giai-doan-03-llm-layer/eval.md`.
