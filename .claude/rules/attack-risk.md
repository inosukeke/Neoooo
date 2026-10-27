---
paths:
  - "src/secgraph/analysis/attack_path/**"
  - "src/secgraph/analysis/risk/**"
---

# Attack path & risk scoring — quy tắc

Entry point (asset public-facing + có lỗ hổng) và crown jewel (asset criticality cao) là **business context**, không suy ra được từ Nmap/CVE — phải gán tay property `exposure` (Service) / `asset_criticality` (Asset) trước khi script chạy.

BFS = reachability/ít bước nhất; Dijkstra = chi phí thấp nhất theo `cost` trên `CONNECTS_TO` — hai thuật toán có thể cho hai đường khác nhau, đừng lẫn. Betweenness centrality = choke point (nhiều shortest path đi qua).

**Công thức risk score (nhân, không cộng — một nhân tử = 0 phải triệt tiêu rủi ro)**:
```
exploit_likelihood = 1.0 nếu in_kev else epss
risk_score = cvss_norm × exploit_likelihood × criticality_norm × reachable
cost = (1 - risk_score) * 9 + 1   # ghi đè CONNECTS_TO.cost
```
PageRank (đã học) gộp với `asset_criticality` bằng `max()` làm một phần điểm ưu tiên vá.

Sai một nhân tử (ví dụ gán sai `asset_criticality`) kéo sai cả kết quả mạnh hơn phép cộng — đây là rủi ro thật của chính công thức.

Toxic combination: nhiều vấn đề rủi ro thấp nối thành một chuỗi impact cao — đây là lý do dùng attack path graph thay vì chấm điểm CVE rời rạc.

Script: `attack_path.py`, `risk_scoring.py`.

Chi tiết: `docs/giai-doan-04-attack-analysis/`.
