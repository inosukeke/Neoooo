---
paths:
  - "src/ingestion/**"
---

# Nguồn dữ liệu an ninh — parser tay

6 nguồn, viết parser tay (đúng ở quy mô demo, không cần ETL framework):

| Nguồn | Endpoint/format | Field chính |
|---|---|---|
| Nmap | XML `nmaprun>host>status/address/hostnames/ports/port` | host up, port open, service |
| NVD CVE | `services.nvd.nist.gov/rest/json/cves/2.0`, header `apiKey` | cveId, cvss (v3.1→v3.0→v2) |
| EPSS | `api.first.org/data/v1/epss` (gộp CVE bằng dấu phẩy) | epss, percentile |
| CISA KEV | JSON tĩnh `cisa.gov/.../known_exploited_vulnerabilities.json`, cần User-Agent giả | cveID, dueDate, knownRansomwareCampaignUse |
| Identity | Giả lập Python (không có AD thật) | user/account/group |
| Log mẫu | EVTX-ATTACK-SAMPLES bản JSON đã chuẩn hóa | EventID 4624/4625 |

Nguyên tắc: pipeline idempotent (nối MERGE ở `graph-schema.md`), cache response ra file, backoff khi 429, fetch gia tăng theo `lastModStartDate/lastModEndDate` (NVD tối đa 120 ngày/lần), validate schema trước khi xuất.

Output chuẩn hóa: xuất JSON vào `normalized/` theo schema chung tạm (asset/service/vulnerability/user/account/alert) — **chưa nối thẳng vào loader Neo4j**, phải qua entity resolution trước khi nạp.

API key qua biến môi trường (xem `security.md`).

Script: `sources.py`.

Chi tiết: `docs/giai-doan-02-data-pipeline/nguon-du-lieu.md`.
