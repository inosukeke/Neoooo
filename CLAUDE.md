# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Đồ thị tri thức an ninh — Demo VinSOC

## Mục tiêu & chiến lược
Demo 8 tuần để vào chương trình fresher AI tại VinSOC (11 đề tài, 20 slot, đánh giá sau 1 tháng thực tập). Cạnh tranh trên trục **đồ thị + LLM + kỹ thuật dữ liệu**, không phải trục security thuần (ai cũng mạnh phần đó).

Sản phẩm: đồ thị tri thức an ninh thu nhỏ (Nmap + CVE/EPSS/KEV + dữ liệu user) → lớp LLM hỏi đáp tiếng Việt sinh Cypher (Text2Cypher + GraphRAG) → tính attack path và thứ tự ưu tiên vá.

Liên quan chính tới đề tài VinSOC #1 (Exposure Management & Attack Path Prediction), #2 (Context Intelligence & Security KG), #7 (Graph Application in Cybersecurity), #8 (AI Assistant/Text2SQL analog). Chi tiết: `docs/00-tong-quan/chien-luoc.md`.

## Trạng thái hiện tại (2026-10-27)
Git repo đã init. **Giai đoạn 01 đã code xong cả 3 module**: `src/graph/seed_graph.py` (schema v1), `src/graph/model_v2.py` (migrate lên schema v2 + 8 câu hỏi kiểm), và `src/graph/algo/algo_demo.py` (thuật toán đồ thị GDS). Cả ba đã chạy thật trên Neo4j 5.26 Community + **GDS 2.13.13** (Docker, no-auth) + driver `neo4j` 6.4.0, xác nhận idempotent và đúng 100% số liệu/câu hỏi/bảng kết quả mong đợi (xem "Đã chạy thật" trong `docs/giai-doan-01-graph-foundations/neo4j-cypher.md`, `mo-hinh-hoa-du-lieu.md`, `thuat-toan-do-thi.md`). **Dữ liệu dạy khái niệm này đã bị `load_graph.py --reset` xóa thay bằng dữ liệu pipeline Giai đoạn 02 thật (xem dưới)** — `seed_graph.py`/`model_v2.py`/`algo_demo.py` vẫn giữ nguyên làm tài liệu học, không còn phản ánh đúng DB hiện tại nếu chạy lại.

**Giai đoạn 02 đã code xong cả 3 module + bước loader**:
- *Module 1 (parser nguồn)*: `gen_fixtures.py` sinh mọi dữ liệu nguồn giả vào `src/ingestion/data/` (Nmap XML, log, AD view, HR view, `er_truth.json`); `sources.py` chuẩn hóa tất cả + gọi API công khai NVD/EPSS/KEV thật → 7 file `src/ingestion/normalized/*.json`. Asset/User **đa-nguồn**: 55 asset (nmap 21 + ad 21 + log 13), 31 user (idp 16 + hr 15), 33 service, 28 vulnerability đủ 3 nguồn, 16 account, 21 membership, 30 alert. Cache API commit ở `src/ingestion/cache/` → offline/idempotent.
- *Module 2 (entity resolution)*: `src/ingestion/resolution/entity_resolution.py` **thuần xử lý**. Gộp asset (55 id → 26 canonical, union-find ≥3 nguồn) + user (31→17), xuất `src/ingestion/resolved/{crosswalk,review_queue,decisions,eval}.json`. Ngưỡng match=95, eval P=1.0. Idempotent.
- *Loader (`src/graph/load_graph.py`)*: nạp `normalized/`+`resolved/` vào Neo4j theo Schema v2, khóa MERGE `canonical_id`. `ADMIN_TO`/CVE→`Service`/`CONNECTS_TO` suy diễn từ bảng rule viết tay (`src/graph/graph_rules.py` — **giả định nghiệp vụ demo**, không phải dữ liệu đo thật). Đã chạy thật `--reset`: **158 node / 243 relationship**, idempotent (chạy lại số liệu giữ nguyên), `SHOW CONSTRAINTS` có `asset_canonical_id`/`user_canonical_id`.
- *Module 3 (OpenSearch, `src/search/`)*: `index_alerts.py` nhân bản 30 alert gốc → 1653 doc (factor=50 + burst 120 bruteforce DC + 33 scenario S2 D.3: lateral movement/audit cleared/new privilege) qua `canonical.py`, bulk index vào `security-alerts`. `search_alerts.py` (4 query bool DSL: terms agg, date histogram, full-text, term text-vs-keyword). `join_neo4j.py` nối tay OpenSearch→Neo4j qua `asset_canonical_id` (top asset bị logon thất bại + CVE KEV). Đã chạy thật trên OpenSearch 2.17.1 Docker — số liệu khớp kỳ vọng (470 alert thất bại, ast-004/dc-01 top failed-logon, CVE-2017-0144+CVE-2020-1472). **Canonical_id dùng prefix `ast-*`/`usr-*` (đổi từ `asset-*` cũ qua entity_resolution).**

Chi tiết "Đã chạy thật" trong `docs/giai-doan-02-data-pipeline/{nguon-du-lieu,entity-resolution,opensearch}.md` và `docs/giai-doan-01-graph-foundations/mo-hinh-hoa-du-lieu.md` (mục "Nạp từ pipeline Giai đoạn 02").

**Giai đoạn 03 đã code xong cả 3 module (Text2Cypher, GraphRAG, Eval).** Text2Cypher — `src/llm/text2cypher/`: pipeline 6 bước tự viết (không dùng `neo4j-graphrag`/LangChain/MCP Server — xem research đã chạy khi code module này) — `schema_text.py` (sinh schema text từ `db.schema.*` thật), `validator.py` (4 lớp: readonly/syntax/schema/direction — **lớp chính thực tế** vì Neo4j Community không có RBAC, xem `security.md`), `llm_client.py` (SDK `openai` qua gateway OpenAI-compatible, model đọc từ env `TEXT2CYPHER_MODEL`, không hardcode), `prompts.py`+`text2cypher.py` (vòng sửa lỗi tối đa 2 lần, chống prompt injection khi diễn giải kết quả). Đã chạy thật với LLM thật (gateway, model `gpt-4o-mini`): 5/5 câu smoke `status=ok`, 2/2 câu đối kháng ("xóa toàn bộ Asset", "archived núp lời lịch sự") đều an toàn (`rejected_write`/`failed`, node count không đổi 158→158). Chi tiết: `docs/giai-doan-03-llm-layer/text2cypher.md`.

- *GraphRAG (`src/llm/graphrag/`)*: embed câu hỏi → vector index tìm seed node → Cypher mở rộng CỐ ĐỊNH 1-2 hop (không LLM sinh) → ghép context JSON-lines (khử lặp + escape chống prompt injection, đã bịt cả newline injection) → LLM sinh câu trả lời. Embedding qua gateway OpenAI-compatible (`EMBEDDING_MODEL`), chỉ embed `Vulnerability.description` (Alert không có message trong graph). Chữ ký `answer_question(..., model, generate_with_usage)` + `GraphRAGResult` có token/latency cho Eval đo chi phí.
- *Eval (`src/eval/`)*: golden set 43 câu (20 structured / 15 fuzzy / 8 adversarial) ground theo dữ liệu thật trong `normalized/`; execution accuracy (không exact match) + chi phí $/câu + độ trễ p50/p95 theo pipeline + phân loại lỗi 1 nguyên nhân; `judge.py` adapter `deepeval` (import optional, gate gọn — **deepeval 4.1.10 đã cài** trong `requirements.txt`, judge đã chạy live, xem Trạng thái verify); adversarial gate bằng `--include-adversarial`.

**Giai đoạn 04 đã code xong cả 2 module.** *Risk scoring (`src/analysis/risk/`)*: công thức nhân `cvss_norm × exploit_likelihood × criticality_norm × reachable` (một nhân tử = 0 triệt tiêu), `risk_to_cost` ghi đè `CONNECTS_TO.cost`, gán `exposure`/`asset_criticality` bằng `coalesce` (không đạp giá trị tay). *Attack path (`src/analysis/attack_path/`)*: GDS Dijkstra (cost thấp nhất) / BFS (reachability) / betweenness có hướng (choke point) + `path_frequency` bổ sung, lọc entry/crown ngoài bản chiếu, `MissingCostError` khi cạnh thiếu cost. **PageRank đã nối vào `patch_priority`**: `attack_path.pagerank` (GDS `gds.pageRank.stream` trên bản chiếu topology tạm, tự drop) chuẩn hoá 0..1 → `patch_priority = max(pagerank_norm, criticality/5)`; caller (service/CLI) truyền vào, runner giữ thuần. Verify live: `app-01` patch 0.78 (từ PageRank, không phải bội của criticality/5), `pagerank_wired=True`.

**Giai đoạn 05 (UI) đã code xong 2 lớp UI dùng chung logic:** *service layer* `src/pipelines/service.py` (framework-agnostic, bọc Text2Cypher/GraphRAG/risk/attack_path/search + `get_health/get_overview/get_risk_ranking/get_alerts/get_attack_path`, mọi truy vấn chỉ-đọc, risk dry-run, attack path chỉ `gds.*.stream`+drop projection). *UI Streamlit* `src/ui/app.py` (demo tối giản màn Hỏi-đáp). *UI web* `src/api/` (FastAPI: `/health /overview /ask /risk /alerts /attack-path`, Pydantic schema, CORS) + `web/` (Next.js App Router, dark-theme, **cả 5 màn đã code**: Tổng quan/Hỏi-đáp/Đồ thị & đường tấn công/Risk & Patch/Alert; đồ thị tấn công vẽ SVG force-layout tự viết). 15 unit test FastAPI (`tests/test_api.py`, mock service). UI phơi rõ cờ `read_only=true`/`pagerank_wired=false`, không bịa số.

**Trạng thái verify (2026-10-27)**: G03 + G04 đã qua code → review (subagent) → fix → unit test (fake) + ruff sạch, **và đã chạy LIVE** trên stack Docker (Neo4j 5.26 + GDS 2.13.14 + OpenSearch 2.17.1): load/risk/attack_path/schema_text/search integration pass; **eval lớp LLM chạy thật** — 35/43 câu: structured 80%, fuzzy 87%, $0.000259/câu, xem `docs/00-tong-quan/ket-qua-eval.md`. **Adversarial 8 câu ĐÃ chạy live** (data an toàn 8/8 — node 160→160; **injection leak đã vá** bằng guard đầu vào xác định `graphrag_demo.is_injection_attempt` + siết prompt, verify live 0 leak, 0 false-positive trên 35 câu golden). **Judge `deepeval` ĐÃ chạy live** (model qua env `DEEPEVAL_JUDGE_MODEL`) — số còn **sơ bộ** vì "tự chấm tay 10 câu đo đồng thuận judge" **CHƯA làm** (cần người). Fallback chain hiện `gpt-5-nano → gpt-4.1-nano → gpt-4o-mini`; đã verify live cả Text2Cypher lẫn UI web trả lời thật qua gateway (có lúc gpt-5-nano trả 403/503 per-model → tự rơi model kế, xem `llm_client._is_retryable`). **Còn CHƯA làm**: chấm tay 10 câu validate judge, cộng chi phí embedding câu hỏi vào $/câu, scale >10k node. Embedding dùng `text-embedding-3-small`.

Neo4j chạy no-auth cho demo local (`NEO4J_AUTH=none`); script dùng `auth=None` khi không có `NEO4J_PASSWORD`. Có `pytest.ini` + `tests/` (≈345 unit không cần service, pass 100% + ~35 integration cần Neo4j/OpenSearch/LLM thật — 2 trong số đó phá hủy dữ liệu, gate bằng `ALLOW_DESTRUCTIVE_TESTS=1`; `python -m pytest tests/ -v` mặc định bỏ qua integration) và `ruff==0.16.10` + `deepeval==4.1.10` đã pin trong `requirements.txt` (ruff sạch toàn repo). CI GitHub Actions (`.github/workflows/ci.yml`) chạy ruff + unit test mỗi push/PR (cài requirements trừ deepeval để nhanh). Các integration test Neo4j/GDS/OpenSearch (load/risk/attack_path/schema_text/search) đã chạy LIVE pass trên Docker trong phiên verify. Tiến độ bài giảng (lý thuyết, không phải code) theo dõi trong Claude Project (`claude/tien-do-bai-giang.md`), không duplicate ở đây. Lộ trình đầy đủ: `docs/00-tong-quan/lo-trinh.md`.

## Tech stack
- Neo4j 5.26 Community (Docker, bind 127.0.0.1) + GDS 2.13.x
- Python 3.x — `neo4j` driver 6.x, `rapidfuzz`, `opensearch-py` 3.x, `deepeval`
- OpenSearch (Docker single-node, `DISABLE_SECURITY_PLUGIN` chỉ cho dev local)
- LLM cho Text2Cypher/GraphRAG, `temperature=0` khi sinh Cypher

## Cấu trúc thư mục
```
src/
  graph/                 Giai đoạn 01 — schema, seed, migration (model_v2.py); Giai đoạn 02 — loader (load_graph.py)
  graph/algo/            Giai đoạn 01/04 — GDS algorithms, attack path, betweenness
  ingestion/             Giai đoạn 02 — parser Nmap/NVD/EPSS/KEV/identity/log
  ingestion/resolution/  Giai đoạn 02 — entity resolution
  search/                Giai đoạn 02 — OpenSearch index/query
  llm/text2cypher/       Giai đoạn 03
  llm/graphrag/          Giai đoạn 03
  eval/                  Giai đoạn 03
  analysis/attack_path/  Giai đoạn 04
  analysis/risk/         Giai đoạn 04
  pipelines/             Giai đoạn 05 — service layer dùng chung cho mọi UI (service.py)
  ui/                    Giai đoạn 05 — UI Streamlit (app.py)
  api/                   Giai đoạn 05 — FastAPI backend (main.py, schemas.py)
web/                     Giai đoạn 05 — UI web Next.js (App Router, 5 màn)
docs/                    Tài liệu kỹ thuật theo module + link bài giảng gốc (đọc khi cần, không tự load)
.claude/rules/           Quy tắc bắt buộc, tự load khi mở file khớp path
```

## Rule tự load theo path (`.claude/rules/`)
Mỗi rule chỉ load khi mở file trong path khớp glob của nó — không cần tự đi đọc hết, hệ thống tự nạp đúng lúc.

| Rule file | Path glob | Phạm vi |
|---|---|---|
| `security.md` | *(luôn load mọi session)* | Secret, injection, entity resolution risk, PII, GDS allowlist |
| `graph-schema.md` | `src/graph/**`, `src/pipeline/**` | Schema v2: node/relationship, quy tắc MERGE |
| `data-sources.md` | `src/ingestion/**` | Parser Nmap/NVD/EPSS/KEV/identity/log |
| `entity-resolution.md` | `src/ingestion/resolution/**` | Blocking/compare/decision/crosswalk |
| `opensearch.md` | `src/search/**` | Mapping, Query DSL, khi nào dùng OpenSearch vs Neo4j |
| `text2cypher.md` | `src/llm/text2cypher/**` | 6 bước, validate 4 lớp (lớp chính thực tế — Neo4j Community không có RBAC) |
| `graphrag.md` | `src/llm/graphrag/**` | Vector index, Cypher mở rộng cố định, prompt injection |
| `graph-algorithms.md` | `src/graph/algo/**`, `src/analysis/**` | GDS: BFS/Dijkstra/PageRank/Louvain/betweenness |
| `attack-risk.md` | `src/analysis/attack_path/**`, `src/analysis/risk/**` | Công thức risk score, entry point/crown jewel |
| `eval.md` | `src/eval/**` | Golden set, execution accuracy, deepeval |

## Quy tắc chung
1. **Schema v2** (`docs/giai-doan-01-graph-foundations/mo-hinh-hoa-du-lieu.md`) là nguồn sự thật duy nhất cho đồ thị. Không tự đổi field/relationship khi chưa cập nhật file đó.
2. Mọi script nạp dữ liệu phải **chạy lặp được** (idempotent): MERGE theo khóa duy nhất, SET phần còn lại, không CREATE trùng.
3. Trước khi code một phần, đọc rule/doc tương ứng (tự load theo path khi mở file trong `src/...`). Nếu phần đó chưa có trong tiến độ bài giảng (theo dõi trong Claude Project, không duplicate ở đây), hỏi lại Chinh, không tự bịa phạm vi.
4. Bảo mật: xem `.claude/rules/security.md` (luôn load mọi session).
5. Các bài giảng gốc hầu hết **chưa chạy thử trên Neo4j/GDS/OpenSearch thật** (sandbox viết bài không có Docker). Khi code, luôn tự verify lại — không tin 100% cú pháp/API trong docs nếu đã lâu, tra lại tài liệu khi nghi ngờ.
6. Dữ liệu demo giả lập (Nmap/NVD/EPSS/KEV mẫu, identity giả) — không có hạ tầng thật, không gọi API thật tới hệ thống production nào.
