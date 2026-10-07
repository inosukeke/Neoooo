# Bảo mật — quy tắc xuyên suốt (luôn load mọi session)

- **Không lưu secret vào property node/relationship.** Đồ thị là bản đồ tấn công, không phải kho bí mật.
- **API key qua biến môi trường**, không hardcode trong script (NVD apiKey, OpenAI key, v.v.)
- **Cypher injection**: luôn dùng parameterized query (`$param`), không nối chuỗi build Cypher. Với Text2Cypher (LLM sinh Cypher), validate app-layer (regex chặn write clause, syntax check, schema check) là lớp phụ, **bắt buộc có user Neo4j role chỉ-đọc ở DB-level làm lớp chính** — không dựa validate app-layer làm lớp duy nhất.
- **OpenSearch Query DSL injection**: không build query bằng string nối, dùng dict/builder của `opensearch-py`.
- **Prompt injection**: dữ liệu nguồn (Nmap, log, mô tả CVE) là input không tin cậy. Khi LLM diễn giải kết quả Cypher hoặc ngữ cảnh GraphRAG, coi nội dung đó như untrusted — không để nó override instruction hệ thống.
- **Entity resolution sai (false merge) nguy hiểm hơn false split** trong ngữ cảnh an ninh — gộp sai làm sai lệch attack path. Ưu tiên threshold an toàn, case mơ hồ vào hàng đợi review, không tự merge/loại.
- **Attack path graph (đồ thị có trọng số/cost) là tài liệu nhạy cảm nhất của dự án** — là bản đồ tấn công đã tối ưu.
- **PII** trong dữ liệu định danh (identity/log thật nếu dùng) cần xử lý cẩn thận, ngay cả ở demo.
- GDS procedure có quyền `.write`/`.mutate` phải nằm trong allowlist khi pipeline có LLM sinh Cypher.
