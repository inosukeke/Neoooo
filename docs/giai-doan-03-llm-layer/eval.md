# Eval cho lớp LLM trên đồ thị

Bài giảng gốc: https://claude.ai/artifact/1otE2WXyD4E3JyhwXShDpV

Chi tiết quy tắc: `../../.claude/rules/eval.md`.

## Quyết định chính
- Golden set 40-50 câu (phân bố 20/15/5-10), chạy song song cả hai pipeline, log đầy đủ trước khi tính metric
- Execution accuracy (Text2Cypher) đáng tin hơn exact match; tách retrieval/generation metric (GraphRAG) qua DeepEval
- Dùng thư viện (DeepEval/Ragas) cho LLM-as-judge, không tự viết lại cơ chế — nhưng tự kiểm judge bằng 10 câu chấm tay

## Cắt
Tự viết LLM-as-judge từ đầu, benchmark Text2Cypher công khai (schema khác, chỉ tham khảo thiết kế).

## Còn nợ khi code thật
- **Chưa chạy thật** — phụ thuộc `text2cypher.py` và `graphrag_demo.py` đã chạy được trên Neo4j thật
- API `deepeval` viết theo tài liệu tại thời điểm viết bài — `pip show deepeval` + đọc docstring trước khi tin cú pháp
- `golden.json` 40-50 câu thật chưa viết, bài chỉ có 10 câu ví dụ
- Bài cuối Giai đoạn 03.

Script: `eval_harness.py`.
