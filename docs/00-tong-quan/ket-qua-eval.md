# Kết quả Eval lớp LLM — số đo THẬT

> Chạy live trên stack Docker (Neo4j 5.26 + GDS 2.13.14, OpenSearch 2.17.1) với gateway LLM
> OpenAI-compatible thật. Đây là số đo thật để trích dẫn (CV/phỏng vấn), kèm đầy đủ caveat.
> Ngày chạy: 2026-10-27.

## Thiết lập
- **Chat model:** fallback chain theo GIÁ thấp→cao `gpt-5-nano → gpt-4.1-nano → gpt-4o-mini`
  (env `LLM_MODEL_CHAIN`, hàm `llm_client.chat_fallback` — lỗi retryable 5xx/429/timeout/
  model-không-có thì thử model kế). Thực tế `gpt-5-nano` trả 503 (gateway "group gemini"
  không có channel) nên pipeline **tự rơi xuống `gpt-4o-mini`** (5 kênh, ổn định) — số đo dưới
  đây là của `gpt-4o-mini`.
- **Embedding model:** `text-embedding-3-small` (embed 28 mô tả CVE vào vector index Neo4j).
- **Bộ câu hỏi:** golden set 35/43 câu đã chạy — **20 structured** (Text2Cypher) + **15 fuzzy**
  (GraphRAG). Nhóm **8 adversarial CHƯA chạy** (gate `--include-adversarial`, bắn câu ghi/xóa
  thẳng vào DB — chạy riêng khi cần).
- **Metric:** execution accuracy (không exact-match): câu đúng khi pipeline trả kết quả thỏa
  tiêu chí `expected` (nonempty / contains giá trị thật / contains_any). Chi phí tính từ token
  usage thật × đơn giá; độ trễ đo end-to-end mỗi câu.

## Kết quả

| Nhóm | Pipeline | Execution accuracy |
|---|---|---|
| structured | Text2Cypher | **16/20 = 80%** |
| fuzzy | GraphRAG | **13/15 = 87%** |
| **Tổng** | | **29/35 ≈ 83%** |

**Chi phí:** tổng **$0.0091**, trung bình **$0.000259/câu** (đơn giá list `gpt-4o-mini`:
$0.15/1M token vào, $0.60/1M token ra).

**Độ trễ (bỏ câu lỗi hạ tầng):**

| Pipeline | p50 | p95 | n |
|---|---|---|---|
| Text2Cypher | 4050 ms | 8058 ms | 20 |
| GraphRAG | 3839 ms | 45113 ms | 15 |

**Phân loại lỗi (6 câu sai, mỗi câu đúng 1 nguyên nhân):**
- `empty_result` × 4 (Text2Cypher sinh Cypher chạy được nhưng trả rỗng → chưa khớp `expected`)
- `generation_miss` × 1 (GraphRAG: đáp án có trong context nhưng câu trả lời thiếu)
- `retrieval_miss` × 1 (GraphRAG: đáp án không nằm trong seed/context truy hồi)

## Caveat (đọc kỹ trước khi trích dẫn)
- **Đơn giá là list-price `gpt-4o-mini` của OpenAI**, không phải giá thực của gateway dùng —
  con số $/câu mang tính ước lượng bậc độ lớn, không phải hóa đơn thật.
- **Chi phí embedding câu hỏi GraphRAG CHƯA được cộng** (callback embed không trả usage).
- **Judge deepeval (contextual precision/recall, faithfulness) CHƯA chạy** — `deepeval` chưa
  cài; do đó CHƯA có metric retrieval/generation tách riêng, và CHƯA "tự chấm tay 10 câu đo
  đồng thuận judge" như rule `eval.md` yêu cầu.
- **Chạy 1 lần, chưa đo variance** (nhiệt độ sinh Cypher = 0 nên Text2Cypher khá tất định;
  GraphRAG/diễn giải vẫn có dao động). Golden set nhỏ (35 câu) → khoảng tin cậy rộng.
- **Adversarial (8 câu) chưa chạy** → chưa có số về chặn read-only/injection ở mức eval.
- `p95` GraphRAG cao (≈45s) do vài câu gọi gateway chậm — không phải lỗi logic.

## Việc tiếp để số mạnh hơn (nợ)
1. Cài `deepeval` + chạy judge cho fuzzy; tự chấm tay 10 câu đo đồng thuận.
2. Chạy nhóm adversarial (đo chặn write/injection live).
3. Cộng chi phí embedding; đổi đơn giá sang giá gateway thật.
4. Chạy nhiều lần (3–5) lấy mean ± std; soi 4 câu `empty_result` (golden quá chặt hay LLM sai).
