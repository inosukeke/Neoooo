# Đồ thị tri thức an ninh — Demo VinSOC

Xem [CLAUDE.md](CLAUDE.md) để biết mục tiêu, tech stack và cấu trúc thư mục đầy đủ. File này chỉ ghi cách chạy phần đã code.

## Giai đoạn 01 — Neo4j & Cypher (schema v1)

### 1. Dựng Neo4j + GDS
```bash
docker run -d --name neo4j-sec \
  -p 127.0.0.1:7474:7474 -p 127.0.0.1:7687:7687 \
  -e NEO4J_AUTH=none \
  -e NEO4J_PLUGINS='["graph-data-science"]' \
  -v neo4j_sec_data:/data \
  neo4j:5.26-community
```
`NEO4J_AUTH=none` → không cần mật khẩu (demo local, bind 127.0.0.1). `NEO4J_PLUGINS` tự tải GDS 2.13.x khớp Neo4j 5.26 (lần đầu cần mạng). Chờ log `Started.` rồi kiểm:
```bash
docker exec neo4j-sec cypher-shell "RETURN gds.version();"   # ra 2.13.x
```
Hoặc mở `http://localhost:7474` (không cần đăng nhập), chạy `RETURN 1`.

> `NEO4J_AUTH=none` chỉ áp dụng khi volume còn trống (lần đầu). Đã lỡ tạo DB có mật khẩu và muốn bỏ auth mà giữ data: dùng `-e NEO4J_dbms_security_auth__enabled=false` thay cho `NEO4J_AUTH=none`.

### 2. Cấu hình
```bash
cp .env.example .env
# Neo4j no-auth: để trống NEO4J_PASSWORD (script tự dùng auth=None)
pip install -r requirements.txt
```

### 3. Nạp dữ liệu & xác minh (schema v1)
```bash
python src/graph/seed_graph.py
```
Script tạo constraint, nạp schema v1 + dữ liệu mẫu (idempotent — chạy lại nhiều lần vẫn ra cùng số liệu), rồi in: số node/relationship theo nhãn/loại, danh sách user tới được `db-01` trong tối đa 3 và 5 bước, kết quả xác minh cú pháp quantified relationship/`SHORTEST`, và plan `PROFILE` để kiểm index.

Chạy lại lần hai để tự kiểm tính idempotent — số liệu phải giữ nguyên.

## Giai đoạn 01 — Mô hình hóa dữ liệu an ninh (schema v2)

Yêu cầu: đã chạy `seed_graph.py` ở trên (script kiểm 5 Asset trước khi chạy tiếp).
```bash
python src/graph/model_v2.py
```
Migrate v1→v2: thêm `Group`/`Alert`, `MEMBER_OF`/`ADMIN_TO`/`AUTHENTICATED_TO`/`OWNS`/`TRIGGERED_ON`/`INVOLVES`, tách quyền "có thể làm" khỏi "đã quan sát". In kết quả 8 câu hỏi kiểm (mục 6.1 `docs/giai-doan-01-graph-foundations/mo-hinh-hoa-du-lieu.md`) và kiểm cấu trúc node/relationship (kỳ vọng 28/37). Idempotent — chạy lại nhiều lần vẫn ra cùng số liệu.

## Giai đoạn 01 — Thuật toán đồ thị (GDS)

Yêu cầu: Neo4j có GDS (`RETURN gds.version()` ra 2.13.x) và đã chạy `model_v2.py`.
```bash
python src/graph/algo/algo_demo.py
```
Thêm 3 máy lab (vpn-01, jump-01, file-01) + gán `cost` 1–10 (nhỏ = dễ đi) cho 10 cạnh `CONNECTS_TO`, chiếu 2 đồ thị vào RAM (`attack` có hướng/có trọng số; `attack_u` vô hướng), rồi chạy & kiểm **BFS, Dijkstra, PageRank, Louvain, Leiden** theo bảng kết quả mong đợi (mục 6.1 `docs/giai-doan-01-graph-foundations/thuat-toan-do-thi.md`). In `OK/FAIL` từng mục.

Lưu ý: script đưa DB lên **8 Asset / 10 `CONNECTS_TO`**, nên `model_v2.py` chạy lại *sau đó* sẽ báo LỆCH số lượng (đúng thiết kế — algo là trạng thái cuối Giai đoạn 01). Query dọn để quay lại dữ liệu bài trước nằm ở cuối `algo_demo.py`.

## Giai đoạn 02 — Module 1: Parser nguồn dữ liệu

Không cần Neo4j. Chỉ cần `pip install -r requirements.txt` (thêm `requests`). Xuất 7 file JSON chuẩn hóa vào `src/ingestion/normalized/` (chưa nạp Neo4j — việc đó sau Entity resolution).
```bash
python src/ingestion/gen_fixtures.py   # (tùy chọn) sinh lại data/sample_nmap.xml + sample_logs.jsonl
python src/ingestion/sources.py
```
`gen_fixtures.py` sinh dữ liệu mẫu tất định (đã commit sẵn, chỉ chạy khi muốn đổi topology). `sources.py` parse 6 nguồn → `asset/service/vulnerability/user/account/membership/alert`:
- **Nmap** (`data/sample_nmap.xml`) → asset + service; **Identity** sinh tất định (seed=42); **Log** (`data/sample_logs.jsonl`) → alert logon.
- **NVD + EPSS + CISA KEV**: gọi **API công khai thật**, gộp theo `cve_id`. Response cache ở `src/ingestion/cache/` (đã commit) → lần sau chạy **offline/tức thì**, idempotent.

NVD không cần key (tự giới hạn 6s/CVE, ~28 CVE ≈ 3 phút lần đầu); có key free thì đặt `NVD_API_KEY` để nhanh hơn. Dùng `--refresh` để xóa cache và gọi API lại. In số record 7 file + completeness (bao nhiêu CVE đủ cả 3 nguồn) + kiểm CVE-2021-44228.

## Giai đoạn 02 — Module 2: Entity resolution

Cần `rapidfuzz` (đã trong `requirements.txt`). Đọc `normalized/{assets,users,alerts}.json`, xuất vào `src/ingestion/resolved/`.
```bash
python src/ingestion/resolution/entity_resolution.py
```
Gộp bản ghi từ nhiều nguồn về cùng một thực thể → `canonical_id`:
- **Asset — 3 nguồn**: Nmap (ip) + **AD view** (`make_ad_view` tự sinh biến thể tên: hoa/FQDN/rút gọn/đổi tên) + **Log** (computer). Union-find gộp cả 3.
- **User — 2 nguồn**: IdP (`users.json`) + **HR view** (`make_hr_view`: email/bỏ chấm).
- Pipeline: blocking (2 ký tự đầu) → compare (exact trước, rồi `fuzz.ratio`/`token_sort_ratio`) → ngưỡng → union-find → crosswalk giữ mọi id gốc.

**Ngưỡng match=95** (không phải 85), chọn theo `security.md` (false merge nguy hiểm hơn false split); cặp 70–94 vào `review_queue.json` cho người xác nhận tay (gồm bẫy `ws-hr-01`↔`ws-hr-02`). Xuất: `crosswalk.json`, `review_queue.json`, `decisions.json` (audit trail), `eval.json` (precision/recall/F1 ở 3 ngưỡng). `canonical_id` sẽ là khóa MERGE khi nạp Neo4j (bước load, sau module này).
