"""Chấm điểm rủi ro theo ngữ cảnh (Giai đoạn 04) — risk score nhân, ghi đè CONNECTS_TO.cost.

Công thức (PHÉP NHÂN, không cộng — một nhân tử = 0 triệt tiêu rủi ro):

    exploit_likelihood = 1.0 nếu in_kev else epss
    risk_score = (cvss/10) × exploit_likelihood × (asset_criticality/5) × reachable
    cost = (1 - risk_score) * 9 + 1        # 1..10, nhỏ = dễ đi

Cấu trúc file (tách logic khỏi I/O để test không cần Neo4j):
  1. Hàm thuần: compute_risk_score, risk_to_cost, patch_priority, compute_reachable,
     score_assets, build_edge_costs.
  2. Bảng business-context gán tay (EXPOSURE_BY_ROLE, CRITICALITY_BY_ROLE) +
     Cypher SET idempotent.
  3. Runner `run_risk_scoring(driver)` nhận driver tiêm từ ngoài; CLI `main()`.

GIẢ ĐỊNH NGHIỆP VỤ DEMO, KHÔNG PHẢI DỮ LIỆU ĐO THẬT: `exposure` và
`asset_criticality` là business context không suy ra được từ Nmap/CVE; hai bảng
rule bên dưới do người viết gán tay (cùng tinh thần `src/graph/graph_rules.py`).
Sai một giá trị ở đây kéo sai cả risk score (rủi ro của chính phép nhân).

Bảo mật: mọi Cypher dùng tham số ($param), không nối chuỗi; không lưu secret vào
property; đồ thị cost sau chấm điểm là bản đồ tấn công đã tối ưu — nhạy cảm.

Chạy thật (cần Neo4j đã nạp bằng load_graph.py):
    python src/analysis/risk/risk_scoring.py            # chấm + ghi cost
    python src/analysis/risk/risk_scoring.py --dry-run  # chỉ in, không ghi
(NEO4J_URI mặc định bolt://localhost:7687; NEO4J_USER/NEO4J_PASSWORD tuỳ chọn,
không có password thì auth=None.)
"""

import argparse
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

# Chạy trực tiếp `python src/analysis/risk/risk_scoring.py` thì sys.path[0] chỉ là thư
# mục risk/ -> thêm src/graph để import được graph_rules (pytest đã có pythonpath riêng).
_GRAPH_DIR = str(Path(__file__).resolve().parents[2] / "graph")
if _GRAPH_DIR not in sys.path:
    sys.path.insert(0, _GRAPH_DIR)

log = logging.getLogger(__name__)

# ---------- Hằng số ----------
CRITICALITY_MIN, CRITICALITY_MAX = 1, 5
COST_MIN, COST_MAX = 1.0, 10.0
DEFAULT_CRITICALITY = (
    2  # role không có trong bảng: coi là thấp, KHÔNG phải 0 (thang 1..5)
)

# ---------- Bảng business-context GÁN TAY ----------
# GIẢ ĐỊNH NGHIỆP VỤ DEMO — KHÔNG PHẢI SỐ ĐO THẬT. Sai một giá trị là kéo sai cả risk.
# Key là role suy từ hostname bởi graph_rules.asset_role().
# exposure của Service: "public" = hướng internet (entry point), "internal" = nội bộ.
EXPOSURE_BY_ROLE: dict[str, str] = {
    "web": "public",
    "vpn": "public",
    "mail": "public",
    "proxy": "public",
}
DEFAULT_EXPOSURE = "internal"

# GIẢ ĐỊNH NGHIỆP VỤ DEMO — không phải số đo. asset_criticality 1..5 (5 = crown jewel).
CRITICALITY_BY_ROLE: dict[str, int] = {
    "dc": 5,
    "db": 5,
    "hypervisor": 5,
    "file": 4,
    "ci": 4,
    "scm": 4,
    "app": 3,
    "mail": 3,
    "vpn": 3,
    "web": 3,
    "proxy": 2,
    "workstation": 2,
}


def asset_role_of(hostname: str) -> str:
    """Role của asset theo prefix hostname — tái sử dụng rule của graph_rules."""
    from graph_rules import (
        asset_role,
    )  # import trễ: hàm thuần phía trên không phụ thuộc yaml

    return asset_role(hostname)


def criticality_for(hostname: str) -> int:
    return CRITICALITY_BY_ROLE.get(asset_role_of(hostname), DEFAULT_CRITICALITY)


def exposure_for(hostname: str) -> str:
    return EXPOSURE_BY_ROLE.get(asset_role_of(hostname), DEFAULT_EXPOSURE)


# ---------- Hàm thuần ----------
def compute_risk_score(
    *,
    cvss: float,
    epss: float,
    in_kev: bool,
    asset_criticality: int,
    reachable: bool,
) -> float:
    """risk_score = cvss_norm × exploit_likelihood × criticality_norm × reachable_f.

    Raise ValueError nếu cvss ngoài 0..10, epss ngoài 0..1, criticality ngoài 1..5.
    Kết quả clamp vào [0,1].
    """
    if not 0.0 <= cvss <= 10.0:
        raise ValueError(f"cvss phải trong 0..10, nhận {cvss!r}")
    if not 0.0 <= epss <= 1.0:
        raise ValueError(f"epss phải trong 0..1, nhận {epss!r}")
    if not CRITICALITY_MIN <= asset_criticality <= CRITICALITY_MAX:
        raise ValueError(
            f"asset_criticality phải trong {CRITICALITY_MIN}..{CRITICALITY_MAX}, "
            f"nhận {asset_criticality!r}"
        )
    exploit_likelihood = 1.0 if in_kev else epss
    cvss_norm = cvss / 10.0
    criticality_norm = asset_criticality / 5.0
    reachable_f = 1.0 if reachable else 0.0
    score = cvss_norm * exploit_likelihood * criticality_norm * reachable_f
    return max(0.0, min(1.0, score))


def risk_to_cost(risk_score: float) -> float:
    """cost = (1 - risk_score) * 9 + 1 → 1..10 (risk cao = cost thấp = dễ đi)."""
    if not 0.0 <= risk_score <= 1.0:
        raise ValueError(f"risk_score phải trong 0..1, nhận {risk_score!r}")
    return (1.0 - risk_score) * (COST_MAX - COST_MIN) + COST_MIN


def patch_priority(pagerank_norm: float, asset_criticality: int) -> float:
    """Điểm ưu tiên vá = max(pagerank_norm, asset_criticality/5)."""
    if not 0.0 <= pagerank_norm <= 1.0:
        raise ValueError(f"pagerank_norm phải trong 0..1, nhận {pagerank_norm!r}")
    if not CRITICALITY_MIN <= asset_criticality <= CRITICALITY_MAX:
        raise ValueError(
            f"asset_criticality phải trong {CRITICALITY_MIN}..{CRITICALITY_MAX}, "
            f"nhận {asset_criticality!r}"
        )
    return max(pagerank_norm, asset_criticality / 5.0)


@dataclass
class AssetRisk:
    canonical_id: str
    hostname: str
    risk_score: float
    cost: float
    patch_priority: float
    drivers: dict = field(default_factory=dict)  # nhân tử đầu vào để giải thích


def compute_reachable(entry_ids: set[str], edges: list[tuple[str, str]]) -> set[str]:
    """BFS từ các entry point (asset có Service exposure=public) qua CONNECTS_TO.

    Trả tập canonical_id có đường tới (gồm chính entry point). Không có entry
    point → tập rỗng → mọi risk = 0 (đúng ý nghĩa nhân tử reachable).
    """
    adj: dict[str, list[str]] = {}
    for src, dst in edges:
        adj.setdefault(src, []).append(dst)
    seen = set(entry_ids)
    queue = deque(sorted(entry_ids))
    while queue:
        cur = queue.popleft()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def score_assets(
    assets: list[dict],
    reachable_ids: set[str],
    pagerank: dict[str, float] | None = None,
) -> list[AssetRisk]:
    """Chấm từng asset; xếp hạng giảm dần theo risk_score (hoà: patch_priority, id).

    `assets`: list dict {canonical_id, hostname, asset_criticality, vulns: [{cve, cvss,
    epss, kev}]}. Risk của asset = max risk các vuln của nó (lỗ hổng tệ nhất quyết
    định); không vuln → 0. Vuln thiếu cvss bị bỏ qua (không bịa số); epss thiếu → 0.
    `pagerank`: canonical_id → PageRank đã chuẩn hoá 0..1; thiếu → 0.0.
    Vuln gây ValueError (dữ liệu bẩn: cvss/epss ngoài khoảng) bị log + bỏ qua. Vuln được
    duyệt theo (cvss giảm dần, cve) để `top_cve` tất định giữa các lần chạy.
    """
    pagerank = pagerank or {}
    result: list[AssetRisk] = []
    for a in assets:
        crit = a.get("asset_criticality")
        if crit is None:
            crit = criticality_for(a["hostname"])
        reach = a["canonical_id"] in reachable_ids
        best_score, best_vuln = 0.0, None
        vulns = sorted(
            a.get("vulns") or [],
            key=lambda v: (-(v.get("cvss") or 0.0), str(v.get("cve"))),
        )
        for v in vulns:
            if v.get("cvss") is None:
                continue
            try:
                s = compute_risk_score(
                    cvss=float(v["cvss"]),
                    epss=float(v.get("epss") or 0.0),
                    in_kev=bool(v.get("kev")),
                    asset_criticality=int(crit),
                    reachable=reach,
                )
            except ValueError as exc:
                log.warning(
                    "Bỏ qua vuln %s của %s: %s", v.get("cve"), a["canonical_id"], exc
                )
                continue
            if best_vuln is None or s > best_score:
                best_score, best_vuln = s, v
        drivers = {
            "asset_criticality": int(crit),
            "reachable": reach,
            "vuln_count": len(a.get("vulns") or []),
            "top_cve": best_vuln.get("cve") if best_vuln else None,
            "cvss": best_vuln.get("cvss") if best_vuln else None,
            "epss": best_vuln.get("epss") if best_vuln else None,
            "in_kev": bool(best_vuln.get("kev")) if best_vuln else False,
        }
        result.append(
            AssetRisk(
                canonical_id=a["canonical_id"],
                hostname=a["hostname"],
                risk_score=best_score,
                cost=risk_to_cost(best_score),
                patch_priority=patch_priority(
                    pagerank.get(a["canonical_id"], 0.0), int(crit)
                ),
                drivers=drivers,
            )
        )
    result.sort(key=lambda r: (-r.risk_score, -r.patch_priority, r.canonical_id))
    return result


def build_edge_costs(
    edges: list[tuple[str, str]], risks: list[AssetRisk]
) -> list[dict]:
    """Cost của cạnh src→dst = risk_to_cost(risk của dst) (chi phí 'bước vào' dst).

    Quy ước demo: dst rủi ro cao → bước vào dễ → cost thấp. dst không có risk → cost 10.
    """
    cost_by_id = {r.canonical_id: r.cost for r in risks}
    return [{"src": s, "dst": d, "cost": cost_by_id.get(d, COST_MAX)} for s, d in edges]


# ---------- Cypher (parameterized, idempotent) ----------
# Gán business-context: chỉ MATCH theo khóa + SET property, không tạo node.
# coalesce: KHÔNG đè giá trị đã gán tay trong DB, chỉ điền chỗ đang null.
SET_ASSET_CRITICALITY_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.canonical_id})
SET a.asset_criticality = coalesce(a.asset_criticality, row.asset_criticality)"""

SET_SERVICE_EXPOSURE_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.canonical_id})-[:RUNS]->(s:Service)
SET s.exposure = coalesce(s.exposure, row.exposure)"""

READ_ASSETS_QUERY = """MATCH (a:Asset)
OPTIONAL MATCH (a)-[:RUNS]->(s:Service)-[hv:HAS_VULN]->(v:Vulnerability)
WHERE hv.status = 'open'
WITH a, collect(DISTINCT CASE WHEN v IS NULL THEN NULL ELSE
     {cve: v.cve, cvss: v.cvss, epss: v.epss, kev: v.kev} END) AS vulns
RETURN a.canonical_id AS canonical_id, a.hostname AS hostname,
       a.asset_criticality AS asset_criticality, vulns"""

READ_ENTRY_POINTS_QUERY = """MATCH (a:Asset)-[:RUNS]->(s:Service {exposure: $exposure})
RETURN DISTINCT a.canonical_id AS canonical_id"""

READ_EDGES_QUERY = """MATCH (a:Asset)-[:CONNECTS_TO]->(b:Asset)
RETURN a.canonical_id AS src, b.canonical_id AS dst"""

WRITE_COST_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.src}), (b:Asset {canonical_id: row.dst})
MERGE (a)-[r:CONNECTS_TO]->(b)
SET r.cost = row.cost"""


# ---------- Runner (driver tiêm từ ngoài) ----------
def _read(driver, query: str, **params) -> list[dict]:
    with driver.session() as session:
        return [rec.data() for rec in session.run(query, **params)]


def _write(driver, query: str, **params) -> None:
    with driver.session() as session:
        session.run(query, **params).consume()


def apply_business_context(driver, assets: list[dict]) -> None:
    """Điền asset_criticality (Asset) + exposure (Service) từ bảng tay CHỈ khi đang null.

    Idempotent và non-destructive: giá trị người dùng đã gán tay trong DB được giữ nguyên.
    """
    crit_rows = [
        {
            "canonical_id": a["canonical_id"],
            "asset_criticality": criticality_for(a["hostname"]),
        }
        for a in assets
    ]
    exp_rows = [
        {"canonical_id": a["canonical_id"], "exposure": exposure_for(a["hostname"])}
        for a in assets
    ]
    _write(driver, SET_ASSET_CRITICALITY_QUERY, rows=crit_rows)
    _write(driver, SET_SERVICE_EXPOSURE_QUERY, rows=exp_rows)


def run_risk_scoring(
    driver,
    *,
    pagerank: dict[str, float] | None = None,
    assign_context: bool = True,
    write: bool = True,
) -> list[AssetRisk]:
    """Đọc đồ thị → chấm risk → (tuỳ chọn) ghi đè CONNECTS_TO.cost → trả list xếp hạng.

    `driver`: đối tượng có `.session()` (neo4j.Driver hoặc fake khi test).
    `assign_context`: điền asset_criticality/exposure từ bảng tay trước khi đọc, chỉ
    chỗ đang null (coalesce, không đè giá trị gán tay).
    `write=False`: không ghi cost. (CLI --dry-run còn tắt cả assign_context.)
    `pagerank`: NỢ có chủ đích — runner chưa tự gọi GDS PageRank; mặc định 0.0 nên
    patch_priority hiện chỉ phản ánh criticality/5. Hook tham số đã sẵn để nối sau
    (module Attack path).
    """
    if assign_context:
        base = _read(
            driver,
            "MATCH (a:Asset) RETURN a.canonical_id AS canonical_id, a.hostname AS hostname",
        )
        apply_business_context(driver, base)
    assets = _read(driver, READ_ASSETS_QUERY)
    for a in assets:
        a["vulns"] = [v for v in (a.get("vulns") or []) if v]
    entry_ids = {
        r["canonical_id"]
        for r in _read(driver, READ_ENTRY_POINTS_QUERY, exposure="public")
    }
    edges = [(r["src"], r["dst"]) for r in _read(driver, READ_EDGES_QUERY)]
    reachable = compute_reachable(entry_ids, edges)
    risks = score_assets(assets, reachable, pagerank)
    if write:
        _write(driver, WRITE_COST_QUERY, rows=build_edge_costs(edges, risks))
    return risks


def format_ranking(risks: list[AssetRisk], top: int = 15) -> str:
    lines = [
        f"{'#':>2} {'canonical_id':<14}{'hostname':<14}{'risk':>6}{'cost':>6}{'patch':>6}  top_cve"
    ]
    for i, r in enumerate(risks[:top], 1):
        d = r.drivers
        lines.append(
            f"{i:>2} {r.canonical_id:<14}{r.hostname:<14}{r.risk_score:>6.2f}"
            f"{r.cost:>6.2f}{r.patch_priority:>6.2f}  {d.get('top_cve') or '-'}"
            f"{' [KEV]' if d.get('in_kev') else ''}{'' if d.get('reachable') else ' [unreachable]'}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="Chấm risk score và ghi đè CONNECTS_TO.cost"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="chỉ in bảng, không ghi cost"
    )
    parser.add_argument("--top", type=int, default=15)
    args = parser.parse_args(argv)

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    auth = (user, password) if password else None
    with GraphDatabase.driver(uri, auth=auth) as driver:
        risks = run_risk_scoring(
            driver, write=not args.dry_run, assign_context=not args.dry_run
        )
    print(format_ranking(risks, args.top))
    print(
        f"\n{len(risks)} asset; {'DRY-RUN (không ghi cost)' if args.dry_run else 'đã ghi CONNECTS_TO.cost'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
