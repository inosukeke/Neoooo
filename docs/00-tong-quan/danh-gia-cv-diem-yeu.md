# Đánh giá project cho CV — điểm mạnh, điểm yếu, cách trình bày

> Góc nhìn: project cá nhân đưa vào CV ứng tuyển **fresher AI @ VinSOC** (trục đồ thị + LLM + kỹ thuật dữ liệu). Viết thẳng, ưu tiên trung thực — vì nhà tuyển dụng VinSOC là dân security/AI, họ sẽ soi đúng những chỗ yếu bên dưới trong phỏng vấn.
>
> Cập nhật: 2026-10-26. Dựa trên trạng thái đã verify live (Neo4j 5.26 + GDS 2.13.14 + OpenSearch 2.17.1 trên Docker).

---

## 1. Điểm MẠNH đáng đưa lên CV (nói thật)

Đây là những thứ **thực sự có** và hiếm gặp ở CV fresher:

- **Kiến trúc end-to-end 5 giai đoạn**, không phải một notebook lẻ: thu thập/chuẩn hóa dữ liệu → entity resolution → đồ thị tri thức (Neo4j) → tìm kiếm log (OpenSearch) → lớp LLM hỏi-đáp → phân tích attack path + risk. Thể hiện tư duy hệ thống.
- **Đồ thị tri thức an ninh thật trên Neo4j + GDS**: schema v2 có chủ đích (tách `CAN_ACCESS`/`ADMIN_TO` "có thể làm" khỏi `AUTHENTICATED_TO` "đã quan sát"), chạy được GDS Dijkstra/BFS/**betweenness centrality** (choke point) — đã verify live ra **9 attack path** và choke point `app-01`.
- **Text2Cypher + GraphRAG TỰ VIẾT** (không dựa LangChain/`neo4j-graphrag`): hiểu từng bước, không phải gọi framework. Đây là điểm phân biệt mạnh so với CV "dùng LangChain làm chatbot".
- **Ý thức bảo mật rõ**: validate 4 lớp cho Cypher do LLM sinh (chặn write/`CALL`/`SHOW`, tokenize backtick, `EXPLAIN`, sửa hướng quan hệ), chống prompt injection khi diễn giải kết quả (escape tag + newline). Rất đúng "gu" một đơn vị SOC.
- **Entity resolution đa nguồn** (55 asset → 26 canonical, union-find), có hàng đợi review cho case mơ hồ, ưu tiên tránh false-merge — tư duy đúng về rủi ro dữ liệu bẩn.
- **Risk scoring có mô hình**: công thức nhân `CVSS × EPSS/KEV × criticality × reachability` (một nhân tử = 0 triệt tiêu rủi ro), đối chiếu SSVC/CISA; ghi đè `CONNECTS_TO.cost` để attack path dùng — gắn CVE với ngữ cảnh business.
- **Eval harness có tư duy đo lường**: golden set 43 câu (structured/fuzzy/adversarial), execution accuracy (không exact-match), và quan trọng — **đo chi phí $/câu + độ trễ p50/p95**, phân loại lỗi 1 nguyên nhân. Ít fresher nghĩ tới đo cost/latency.
- **Kỷ luật kỹ thuật**: ~344 unit test (dependency injection + fake, không cần service), tách logic khỏi I/O, script idempotent (MERGE), có `.claude/rules` ràng buộc thiết kế. Đã qua vòng **code → review → fix** cho từng module.
- **Đã verify LIVE một phần quan trọng**: load pipeline (số liệu khớp), risk scoring (dc-01 risk 0.88), attack path (GDS thật) chạy thật trên Docker, có integration test pass.

---

## 2. ĐIỂM YẾU / THIẾU SÓT thật (phần quan trọng nhất)

Hình dung một senior/tech lead soi trong phỏng vấn — đây là chỗ họ sẽ hỏi:

### 2.1 Dữ liệu hoàn toàn GIẢ LẬP — rủi ro lớn nhất về "độ thật"
- Nmap, log, AD/HR, identity đều sinh bằng `gen_fixtures.py` (tất định, bịa). Không có scan thật, không có SIEM thật.
- **Quan hệ cốt lõi của attack path là bịa**: `CONNECTS_TO`, `ADMIN_TO`, map CVE→Service suy từ **bảng rule viết tay** (`graph_rules.py`) — code đã ghi rõ "giả định nghiệp vụ demo". Nghĩa là **attack path và risk ranking phản ánh giả định của chính mình**, không phải quan hệ đo được từ dữ liệu thật.
- Hệ quả CV: tuyệt đối **không** được nói "phát hiện đường tấn công trong hệ thống" theo kiểu ngụ ý thật. Đây là mô hình/demo trên dữ liệu mô phỏng.

### 2.2 Lớp LLM CHƯA được verify live đầy đủ — "điểm AI" lại là chỗ mỏng nhất
- **GraphRAG, Eval**: mới chỉ unit test với fake, **chưa chạy thật với LLM/gateway nào**. Vector index (`CREATE VECTOR INDEX`/`db.index.vector.queryNodes`) còn comment "CHƯA verify".
- **Text2Cypher**: có chạy thật với gateway (`gpt-4o-mini`) ở mức smoke 5 câu + 2 câu đối kháng — nhưng không phải đo accuracy có hệ thống.
- **Golden set 43 câu chưa đối chiếu LLM thật**; CVE/giá trị kỳ vọng ground theo dữ liệu nguồn chứ chưa chạy qua pipeline thật.
- `deepeval` **chưa cài** → judge (retrieval/generation metric) chưa chạy lần nào; yêu cầu "tự chấm tay 10 câu đo đồng thuận judge" **chưa làm**.
- Hệ quả CV: **không có một con số accuracy/precision/recall thật nào** cho lớp LLM. Nếu ghi "đạt X% accuracy" là overclaim.

### 2.3 Quy mô nhỏ, chưa có benchmark thật
- 158 node / 243 relationship / 26 asset / 43 câu hỏi. Đủ để minh họa, **chưa chứng minh scale** (performance trên 10k+ node, supernode, chi phí embedding thật).
- Không có bảng số liệu đo thật (accuracy, $/câu, p50/p95) để đưa lên CV — phần "đo lường" hiện là *khả năng của code*, chưa phải *kết quả đã đo*.

### 2.4 Kỹ thuật phần mềm / vận hành còn thiếu
- **Chưa CI/CD**, chưa container hóa ứng dụng (docker-compose chỉ cho Neo4j/OpenSearch, không đóng gói code).
- **Không có UI/demo trực quan** (chỉ CLI + Neo4j Browser) → khó "khoe" trong 30 giây với nhà tuyển dụng.
- **Packaging thủ công**: import phụ thuộc `PYTHONPATH` set tay (sibling imports), không phải package Python chuẩn → chạy standalone dễ `ModuleNotFoundError` (đã phải thêm `sys.path` vá).
- **Test harness cũ còn lỗi**: 5 test `test_schema_text_integration` fail do `neo4j.SessionError: Session closed` (fixture/driver 6.x); 2 test burst lệ thuộc count alert đang trôi (WIP chưa commit `index_alerts.py`: 1653 vs 1620).
- **Nhiều thứ chưa commit**, lịch sử git chưa gọn — nhà tuyển dụng hay xem commit history.

### 2.5 Rủi ro TRÌNH BÀY (overclaim) — dễ mất điểm nhất
- Bài học thực tế vừa xảy ra: `CLAUDE.md` từng ghi `load_graph.py` "đã chạy thật 158 node", nhưng khi chạy live mới lộ **bug cú pháp Cypher** (`SET` đặt trước `ON CREATE SET` ở 6 query) khiến `--reset` chết ngay. → Minh chứng rủi ro **tin tài liệu hơn thực tế**. Trên CV, nếu nói "đã triển khai/chạy production" mà demo lại gãy khi phỏng vấn thì phản tác dụng nặng.
- Các cụm từ cần TRÁNH nếu chưa có bằng chứng: "phát hiện lỗ hổng thật", "giảm X% thời gian vá", "độ chính xác LLM Y%", "triển khai production", "dữ liệu thật".

---

## 3. Thiếu gì để project ĐỦ MẠNH cho CV (ưu tiên)

Xếp từ rẻ-mà-đáng nhất → nên-có:

1. **Chạy lớp LLM thật + có bảng số đo** (quan trọng số 1): cài `deepeval`, chạy `eval_harness` trên golden set với gateway thật → xuất bảng **accuracy theo loại + $/câu + p50/p95**. Chỉ cần 1 bảng số thật là CV mạnh hẳn và chống được câu hỏi "đo thế nào?".
2. **Tự chấm tay 10 câu** để đo đồng thuận với judge trước khi trích số judge (đã nêu trong rule, chưa làm).
3. **README có kiến trúc + ảnh đồ thị (Neo4j Browser) + 1 bảng kết quả** + GIF/video demo 60–90 giây (hỏi tiếng Việt → Cypher → trả lời; attack path trên graph). Đây là thứ nhà tuyển dụng xem đầu tiên.
4. **CI đơn giản** (GitHub Actions chạy `pytest` unit + `ruff`) — rẻ, tạo ấn tượng kỷ luật.
5. **Sửa nốt test harness cũ** (5 schema_text fixture) + commit gọn theo nhóm, để repo "xanh" khi họ clone.
6. **Giảm độ "toàn giả lập"**: cân nhắc scan Nmap thật một lab nhỏ của chính mình (máy ảo/nhà) để có ít nhất một nhánh dữ liệu thật, và **viết rõ mục "Giả định vs Đo thật"** trong README (chính sự trung thực này là điểm cộng với dân security).
7. (nice-to-have) UI nhỏ (Streamlit) bọc Text2Cypher/GraphRAG để demo tương tác.

---

## 4. Gợi ý CÁCH VIẾT trên CV (trung thực mà vẫn mạnh)

Nguyên tắc: nhấn **"tự xây"**, **"đồ thị + LLM"**, **"end-to-end"**, **"ý thức bảo mật & đo lường"**; luôn gắn nhãn **"demo/lab, dữ liệu mô phỏng"**.

**Phiên bản 1 — 1 dòng (CV ngắn):**
> *Security Knowledge Graph (demo cá nhân):* xây đồ thị tri thức an ninh trên Neo4j + GDS với dữ liệu **mô phỏng** (Nmap/CVE/EPSS/KEV), lớp hỏi-đáp tiếng Việt tự viết (Text2Cypher + GraphRAG), tính attack path (Dijkstra/betweenness) và chấm điểm rủi ro theo ngữ cảnh.

**Phiên bản 2 — 3 bullet (CV chi tiết):**
> - Tự thiết kế đồ thị tri thức an ninh (Neo4j, 8 loại node) + pipeline nạp dữ liệu đa nguồn **mô phỏng** có entity resolution; tính attack path & risk scoring bằng Neo4j GDS (Dijkstra, BFS, betweenness).
> - Tự xây lớp LLM Text2Cypher + GraphRAG (không dùng framework), có **validate 4 lớp chống truy vấn ghi/injection** và eval harness đo execution accuracy, chi phí & độ trễ.
> - Kỷ luật kỹ thuật: ~344 unit test, thiết kế theo dependency-injection, docker-compose cho hạ tầng local; chạy thật phần đồ thị/GDS trên Neo4j 5.26 + OpenSearch 2.17.

**Phiên bản 3 — khi được hỏi sâu (nói trong phỏng vấn):**
> "Đây là **demo học tập trên dữ liệu mô phỏng**, mục tiêu là thể hiện cách mình ghép **đồ thị + LLM + kỹ thuật dữ liệu** cho bài toán exposure management. Quan hệ như CONNECTS_TO/ADMIN_TO là **giả định nghiệp vụ mình tự đặt**, không phải đo từ hệ thống thật — nên attack path là minh họa phương pháp. Phần mình tự tin nhất là lớp Text2Cypher tự viết và tư duy bảo mật/eval; phần mình biết còn thiếu là số liệu đo LLM thật và scale."

→ Chính câu "mình biết còn thiếu gì" này thường ghi điểm hơn là khoe quá đà.

---

## 5. Tóm tắt một dòng

Project **đủ tốt để là điểm nhấn CV fresher** nhờ phạm vi end-to-end + tự xây lớp LLM + ý thức bảo mật/eval. Rủi ro lớn nhất không phải thiếu tính năng mà là **trình bày quá lời**: dữ liệu giả lập, quan hệ attack path là giả định, và **chưa có số đo LLM thật**. Việc nên làm trước khi đưa vào CV: chạy eval LLM thật ra 1 bảng số + README có demo trực quan + ghi rõ "giả định vs đo thật".
