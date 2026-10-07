# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Đồ thị tri thức an ninh — Demo VinSOC

## Mục tiêu & chiến lược
Demo 8 tuần để vào chương trình fresher AI tại VinSOC (11 đề tài, 20 slot, đánh giá sau 1 tháng thực tập). Cạnh tranh trên trục **đồ thị + LLM + kỹ thuật dữ liệu**, không phải trục security thuần (ai cũng mạnh phần đó).

Sản phẩm: đồ thị tri thức an ninh thu nhỏ (Nmap + CVE/EPSS/KEV + dữ liệu user) → lớp LLM hỏi đáp tiếng Việt sinh Cypher (Text2Cypher + GraphRAG) → tính attack path và thứ tự ưu tiên vá.

Liên quan chính tới đề tài VinSOC #1 (Exposure Management & Attack Path Prediction), #2 (Context Intelligence & Security KG), #7 (Graph Application in Cybersecurity), #8 (AI Assistant/Text2SQL analog). Chi tiết: `docs/00-tong-quan/chien-luoc.md`.

## Trạng thái hiện tại (2026-10-07)
**Chưa có code nào trong `src/` — toàn bộ là thư mục rỗng (scaffolding).** Chưa phải git repo, chưa có `requirements.txt`/`pyproject.toml`/`docker-compose.yml` hay bất kỳ file cấu hình nào. Vì vậy **chưa có lệnh build/lint/test nào để chạy** — không tự bịa ra (`pip install`, `pytest`, v.v.) khi chưa có manifest thật. Việc code đầu tiên là Giai đoạn 01 (Neo4j schema + seed) trong `src/graph/`.

Tiến độ bài giảng (lý thuyết, không phải code) chi tiết theo dõi trong Claude Project (`claude/tien-do-bai-giang.md`), không duplicate ở đây. Tính đến nay: đã có bài giảng lý thuyết cho Giai đoạn 01–04 (11 module). Lộ trình đầy đủ: `docs/00-tong-quan/lo-trinh.md`.

## Tech stack
- Neo4j 5.26 Community (Docker, bind 127.0.0.1) + GDS 2.13.x
- Python 3.x — `neo4j` driver 6.x, `rapidfuzz`, `opensearch-py` 3.x, `deepeval`
- OpenSearch (Docker single-node, `DISABLE_SECURITY_PLUGIN` chỉ cho dev local)
- LLM cho Text2Cypher/GraphRAG, `temperature=0` khi sinh Cypher

## Cấu trúc thư mục
```
src/
  graph/                 Giai đoạn 01 — schema, seed, migration (model_v2.py)
  graph/algo/            Giai đoạn 01/04 — GDS algorithms, attack path, betweenness
  ingestion/             Giai đoạn 02 — parser Nmap/NVD/EPSS/KEV/identity/log
  ingestion/resolution/  Giai đoạn 02 — entity resolution
  search/                Giai đoạn 02 — OpenSearch index/query
  llm/text2cypher/       Giai đoạn 03
  llm/graphrag/          Giai đoạn 03
  eval/                  Giai đoạn 03
  analysis/attack_path/  Giai đoạn 04
  analysis/risk/         Giai đoạn 04
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
| `text2cypher.md` | `src/llm/text2cypher/**` | 6 bước, validate 4 lớp, readonly DB role |
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
7. Repo chưa init git — khi bắt đầu code thật (Giai đoạn 01), nhớ hỏi Chinh trước khi `git init`/tạo commit đầu tiên, vì đây là quyết định hạ tầng chứ không phải code thường.
