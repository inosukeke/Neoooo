# Entity resolution cho đồ thị an ninh

Bài giảng gốc: https://claude.ai/artifact/SMLz2o66XbR87qhcj4y3Qo

Chi tiết quy tắc: `../../.claude/rules/entity-resolution.md`.

## Quyết định chính
- Fuzzy rule-based đúng ở quy mô demo (so với exact-key, ML có nhãn)
- Blocking theo prefix hostname chuẩn hóa; `rapidfuzz` (`fuzz.ratio`, `fuzz.token_sort_ratio`); union-find gộp cụm khi entity xuất hiện ≥3 nguồn
- Đánh giá bằng precision/recall/F1 trên tập nhãn tay; false merge nguy hiểm hơn false split

## Cắt
Weighted multi-field scoring đầy đủ, active learning/ML matching, blocking nâng cao (minhash/LSH — chỉ cần biết tồn tại).

## Đã chạy thật (2026-10-08)
`src/ingestion/resolution/entity_resolution.py` **thuần xử lý** — đọc `normalized/{assets,users}.json` (đa-nguồn, có field `source`) + `data/er_truth.json` (nhãn eval), KHÔNG tự sinh data. Việc tạo nguồn AD/HR biến thể đã chuyển sang `gen_fixtures.py` (tầng ingestion) để data không trộn với logic. Chạy thật (`rapidfuzz` 3.14.1), idempotent:
- **Asset — 3 nguồn** (Nmap ip + AD view + Log computer): 55 id gốc → **26 canonical_id**. Nguồn AD biến thể (hoa, FQDN `.lab.local`, rút số `web-2`, đổi tên `fileserver-01`/`vcenter`) + máy chỉ-AD (`legacy-nas`) / chỉ-Nmap (`spare-01`) + bẫy `ws-hr-01` (AD không có) — tất cả sinh ở `gen_fixtures.py`.
- **Union-find gộp đúng ≥3 nguồn**: vd `db-01` → 1 cụm {nmap:10.0.3.30, ad:DB-01, log:db-01}.
- **User — 2 nguồn** (IdP + HR view email/bỏ chấm): 31 id → 17 canonical, khớp 100% (dữ liệu sạch, không có case review — đúng như §10 lỗi #1 lưu ý).
- **Eval 3 ngưỡng (asset)**: th70 P=0.96 R=1.0 F1=0.98 (2 false merge); th85 P=0.95 R=0.93; **th95 P=1.0 R=0.91 F1=0.95 (0 false merge)**.

**Quyết định ngưỡng = 95** (không phải 85 ví dụ bài giảng): theo `security.md` false merge nguy hiểm hơn false split, th95 cho precision tuyệt đối. Mọi cặp 70–94 (gồm bẫy `ws-hr-01`↔`ws-hr-02` 87.5đ) rơi `review_queue.json` cho người xác nhận tay — ở th95 bẫy này KHÔNG bị gộp (ws-hr-01 và ws-hr-02 tách đúng 2 cụm), còn ở th85 thì gộp sai. Đây là minh họa trực tiếp vì sao nghiêng precision.

## Còn nợ (bước sau)
- Chưa nối `crosswalk.json` vào loader Neo4j (dùng `canonical_id` làm khóa MERGE) — thuộc bước load sau Module 3.
- Review band cho user hiện rỗng (biến thể email/bỏ chấm đều khớp qua `username_variants`); nếu muốn demo review cho user, thêm biến thể gõ sai/cắt ký tự.

Script: `entity_resolution.py` → output `resolved/{crosswalk,review_queue,decisions,eval}.json`.
