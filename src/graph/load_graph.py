"""Giai đoạn 02→01 — loader nạp toàn bộ dữ liệu pipeline (normalized/ + resolved/
crosswalk.json) vào Neo4j theo Schema v2, khóa MERGE = canonical_id cho Asset/User.

Thay thế toy graph Giai đoạn 01 (seed_graph.py/model_v2.py/algo_demo.py). Chạy lặp
được (idempotent): MERGE theo khóa duy nhất, SET phần còn lại. `ADMIN_TO`, CVE→Service
(map vào HAS_VULN) và CONNECTS_TO là **giả định nghiệp vụ demo** suy từ bảng rule viết
tay (graph_rules.py) — không có nguồn dữ liệu thật cho 3 quan hệ này.

Yêu cầu: Neo4j 5.26 Community đang chạy, NEO4J_URI/USER/PASSWORD trong env (AUTH=None
nếu không có password — demo local NEO4J_AUTH=none). Xem mo-hinh-hoa-du-lieu.md §
"Nạp từ pipeline Giai đoạn 02" và graph-schema.md.

--reset: XÓA SẠCH toy graph Giai đoạn 01 hiện có (kể cả GDS projection attack/attack_u
nếu còn) trước khi nạp. Chỉ dùng khi đã xác nhận với Chinh (xem brief T012).
"""

import argparse
import hashlib
import json
import os
import sys

from graph_rows import (
    build_account_rows,
    build_alert_rows,
    build_asset_rows,
    build_auth_rows,
    build_membership_rows,
    build_service_rows,
    build_user_rows,
    build_vuln_rows,
    load_inputs,
)
from graph_rules import (
    asset_role,
    derive_admin_to,
    derive_connects_to,
    map_service_vulns,
    network_zone,
)
from neo4j import GraphDatabase

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
USER = os.getenv("NEO4J_USER", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD")
# Demo local: cho phép Neo4j không đặt mật khẩu (NEO4J_AUTH=none) — khi đó auth=None.
AUTH = (USER, PASSWORD) if PASSWORD else None

# Số liệu thật đo được ở T007/T008 (xem brief T012) — dùng để verify sau khi nạp.
EXPECT_NODES = {
    "Asset": 26,
    "Network": 3,
    "Service": 33,
    "Vulnerability": 28,
    "User": 17,
    "Account": 16,
    "Group": 5,
    "Alert": 30,
}
EXPECT_RELS = {
    "IN_NETWORK": 21,
    "RUNS": 33,
    "HAS_VULN": 16,
    "HAS_ACCOUNT": 16,
    "MEMBER_OF": 21,
    "ADMIN_TO": 16,
    "CONNECTS_TO": 38,
    "AUTHENTICATED_TO": 22,
    "TRIGGERED_ON": 30,
    "INVOLVES": 30,
}

CONSTRAINTS = [
    "CREATE CONSTRAINT asset_canonical_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.canonical_id IS UNIQUE",
    "CREATE CONSTRAINT asset_hostname IF NOT EXISTS FOR (a:Asset) REQUIRE a.hostname IS UNIQUE",
    "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE",
    "CREATE CONSTRAINT user_canonical_id IF NOT EXISTS FOR (u:User) REQUIRE u.canonical_id IS UNIQUE",
    "CREATE CONSTRAINT user_username IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
    "CREATE CONSTRAINT account_name IF NOT EXISTS FOR (c:Account) REQUIRE c.name IS UNIQUE",
    "CREATE CONSTRAINT network_cidr IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE",
    "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE",
    "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
    "CREATE INDEX alert_time IF NOT EXISTS FOR (a:Alert) ON (a.time)",
    # LoadMeta: node kỹ thuật riêng của loader (không phải Schema v2 nghiệp vụ) —
    # lưu hash crosswalk.json lần nạp gần nhất, xem crosswalk_hash()/guard major #4.
    "CREATE CONSTRAINT loadmeta_key IF NOT EXISTS FOR (m:LoadMeta) REQUIRE m.key IS UNIQUE",
]

GUARD_ASSET = "MATCH (a:Asset) WHERE a.canonical_id IS NULL RETURN count(a) AS n"
GUARD_USER = "MATCH (u:User) WHERE u.canonical_id IS NULL RETURN count(u) AS n"
ASSET_COUNT_QUERY = "MATCH (a:Asset) RETURN count(a) AS n"

GET_CROSSWALK_HASH_QUERY = (
    "MATCH (m:LoadMeta {key: 'crosswalk_hash'}) RETURN m.value AS v"
)
SAVE_CROSSWALK_HASH_QUERY = """MERGE (m:LoadMeta {key: 'crosswalk_hash'})
SET m.value = $hash"""

# Cạnh suy diễn từ bảng rule viết tay (graph_rules.py) — KHÔNG phải dữ liệu nguồn
# thật, nên sau mỗi lần MERGE phải xóa cạnh không còn khớp $rows hiện tại (rule có
# thể đổi giữa 2 lần nạp — xem Fix round 1, major #5). KHÔNG áp dụng cho
# RUNS/MEMBER_OF/IN_NETWORK/AUTHENTICATED_TO/TRIGGERED_ON/INVOLVES (từ dữ liệu
# nguồn thật, không phải rule).
DELETE_STALE_CONNECTS_TO_QUERY = """MATCH (a:Asset)-[r:CONNECTS_TO]->(b:Asset)
WHERE NOT [a.canonical_id, b.canonical_id] IN $pairs
DELETE r"""

DELETE_STALE_ADMIN_TO_QUERY = """MATCH (g:Group)-[r:ADMIN_TO]->(a:Asset)
WHERE NOT [g.name, a.canonical_id] IN $pairs
DELETE r"""

# Chỉ xóa HAS_VULN do map_service_vulns() (CVE_SERVICE_RULES) tạo ra — đánh dấu bằng
# r.derived_by (SET lúc MERGE ở HAS_VULN_QUERY), KHÔNG so theo tập CVE hiện tại
# (Fix round 2, major mới): nếu XÓA HẲN 1 rule, CVE đó không còn trong tập rule mới
# -> so theo tập CVE sẽ bỏ sót cạnh cần xóa. So theo CẶP (service, cve) giống cách
# đã làm cho CONNECTS_TO/ADMIN_TO mới đúng trong mọi trường hợp (đổi version HAY
# xóa hẳn rule). Không đụng HAS_VULN nào khác nếu sau này có nguồn thật khác.
DELETE_STALE_HAS_VULN_QUERY = """MATCH (s:Service)-[r:HAS_VULN]->(v:Vulnerability)
WHERE r.derived_by = 'cve_service_rule' AND NOT [s.id, v.cve] IN $pairs
DELETE r"""

ASSET_QUERY = """UNWIND $rows AS row
MERGE (a:Asset {canonical_id: row.canonical_id})
SET a.hostname = row.hostname, a.ip = row.ip, a.sources = row.sources,
    a.source_ids = row.source_ids, a.in_review = row.in_review, a.role = row.role"""

NETWORK_QUERY = """UNWIND $rows AS row
MERGE (n:Network {cidr: row.cidr})
SET n.zone = row.zone"""

IN_NETWORK_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.asset_canonical_id}), (n:Network {cidr: row.cidr})
MERGE (a)-[:IN_NETWORK]->(n)"""

SERVICE_QUERY = """UNWIND $rows AS row
MERGE (s:Service {id: row.id})
SET s.port = row.port, s.protocol = row.protocol, s.name = row.name,
    s.product = row.product, s.version = row.version"""

RUNS_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.asset_canonical_id}), (s:Service {id: row.id})
MERGE (a)-[:RUNS]->(s)"""

VULN_QUERY = """UNWIND $rows AS row
MERGE (v:Vulnerability {cve: row.cve})
SET v.cvss = row.cvss, v.cvss_severity = row.cvss_severity, v.epss = row.epss,
    v.epss_percentile = row.epss_percentile, v.kev = row.kev,
    v.kev_date_added = CASE WHEN row.kev_date_added IS NULL THEN NULL ELSE date(row.kev_date_added) END,
    v.kev_due_date = CASE WHEN row.kev_due_date IS NULL THEN NULL ELSE date(row.kev_due_date) END,
    v.kev_ransomware = row.kev_ransomware, v.description = row.description"""

HAS_VULN_QUERY = """UNWIND $rows AS row
MATCH (s:Service {id: row.service_id}), (v:Vulnerability {cve: row.cve})
MERGE (s)-[r:HAS_VULN]->(v)
ON CREATE SET r.first_seen = datetime('2026-10-05T00:00:00Z'), r.status = 'open'
SET r.derived_by = 'cve_service_rule'"""

USER_QUERY = """UNWIND $rows AS row
MERGE (u:User {canonical_id: row.canonical_id})
SET u.username = row.username, u.display_name = row.display_name, u.sources = row.sources,
    u.source_ids = row.source_ids"""

ACCOUNT_QUERY = """UNWIND $rows AS row
MERGE (c:Account {name: row.name})
SET c.account_type = row.account_type, c.enabled = row.enabled"""

HAS_ACCOUNT_QUERY = """UNWIND $rows AS row
MATCH (u:User {canonical_id: row.user_canonical_id}), (c:Account {name: row.name})
MERGE (u)-[:HAS_ACCOUNT]->(c)"""

GROUP_QUERY = """UNWIND $rows AS row
MERGE (g:Group {name: row.group})"""

MEMBER_OF_QUERY = """UNWIND $rows AS row
MATCH (c:Account {name: row.account}), (g:Group {name: row.group})
MERGE (c)-[:MEMBER_OF]->(g)"""

ADMIN_TO_QUERY = """UNWIND $rows AS row
MATCH (g:Group {name: row.group}), (a:Asset {canonical_id: row.asset_canonical_id})
MERGE (g)-[:ADMIN_TO]->(a)"""

CONNECTS_TO_QUERY = """UNWIND $rows AS row
MATCH (a:Asset {canonical_id: row.src}), (b:Asset {canonical_id: row.dst})
MERGE (a)-[r:CONNECTS_TO]->(b)
SET r.ports = row.ports, r.rules = row.rules"""

AUTHENTICATED_TO_QUERY = """UNWIND $rows AS row
MATCH (c:Account {name: row.account}), (a:Asset {canonical_id: row.asset_canonical_id})
MERGE (c)-[r:AUTHENTICATED_TO]->(a)
SET r.last_seen = datetime(row.last_seen)"""

ALERT_QUERY = """UNWIND $rows AS row
MERGE (al:Alert {id: row.id})
SET al.time = datetime(row.time), al.event_id = row.event_id, al.success = row.success,
    al.severity = row.severity, al.rule = row.rule
WITH al, row
MATCH (a:Asset {canonical_id: row.asset_canonical_id})
MERGE (al)-[:TRIGGERED_ON]->(a)
WITH al, row
OPTIONAL MATCH (c:Account {name: row.account})
FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END |
  MERGE (al)-[:INVOLVES]->(c))"""


def run(driver, query, **params):
    return driver.execute_query(query, database_="neo4j", **params)


def guard_blocked(driver) -> int:
    """Trả số Asset/User thiếu canonical_id (toy graph cũ còn sót). 0 nghĩa là an toàn."""
    asset_rows, _, _ = run(driver, GUARD_ASSET)
    user_rows, _, _ = run(driver, GUARD_USER)
    return asset_rows[0]["n"] + user_rows[0]["n"]


def crosswalk_hash(crosswalk: dict) -> str:
    """Hash nội dung crosswalk.json (key đã sort) — dùng để phát hiện entity
    resolution chạy lại và đổi canonical_id (xem Fix round 1, major #4): nếu Chinh
    xử lý 1 review_queue entry, thứ tự sort cluster trong build_crosswalk() đổi ->
    MỌI canonical_id phía sau bị dịch số -> node cũ trong Neo4j mang canonical_id
    sai (gắn nhầm hostname/cạnh của asset khác). Hash lệch giữa 2 lần nạp là dấu
    hiệu đáng tin của việc này."""
    raw = json.dumps(crosswalk, sort_keys=True, ensure_ascii=True)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def get_stored_crosswalk_hash(driver) -> str | None:
    rows, _, _ = run(driver, GET_CROSSWALK_HASH_QUERY)
    return rows[0]["v"] if rows else None


def save_crosswalk_hash(driver, crosswalk: dict) -> None:
    run(driver, SAVE_CROSSWALK_HASH_QUERY, hash=crosswalk_hash(crosswalk))


def reset(driver) -> None:
    for name in ("attack", "attack_u"):
        try:
            exists_rows, _, _ = run(
                driver, "CALL gds.graph.exists($name) YIELD exists", name=name
            )
            if exists_rows and exists_rows[0]["exists"]:
                run(driver, "CALL gds.graph.drop($name)", name=name)
        except Exception as exc:  # noqa: BLE001 — GDS có thể không cài / không có graph nào, chỉ log và tiếp tục
            print(f"  (bỏ qua drop GDS graph {name}: {exc})")
    run(driver, "MATCH (n) DETACH DELETE n")


def create_constraints(driver) -> None:
    for c in CONSTRAINTS:
        run(driver, c)


def build_all_rows(data: dict) -> dict:
    cw = data["crosswalk"]
    asset_rows = build_asset_rows(data["assets"], cw, data["review_queue"])
    for row in asset_rows:
        row["role"] = asset_role(row["hostname"])

    cidrs = sorted({r["cidr"] for r in asset_rows if r["cidr"] is not None})
    network_rows = [{"cidr": cidr, "zone": network_zone(cidr)} for cidr in cidrs]
    in_network_rows = [
        {"asset_canonical_id": r["canonical_id"], "cidr": r["cidr"]}
        for r in asset_rows
        if r["cidr"] is not None
    ]

    service_rows = build_service_rows(data["services"], cw)
    vuln_rows = build_vuln_rows(data["vulnerabilities"])
    has_vuln_rows = map_service_vulns(service_rows)

    user_rows = build_user_rows(data["users"], cw)
    account_rows = build_account_rows(data["accounts"], cw)
    membership_rows = build_membership_rows(data["memberships"])
    group_rows = [{"group": g} for g in sorted({m["group"] for m in membership_rows})]

    admin_to_rows = derive_admin_to(asset_rows)
    connects_to_rows = derive_connects_to(asset_rows, service_rows)
    auth_rows = build_auth_rows(data["alerts"], cw)
    alert_rows = build_alert_rows(data["alerts"], cw)

    return {
        "asset": asset_rows,
        "network": network_rows,
        "in_network": in_network_rows,
        "service": service_rows,
        "vuln": vuln_rows,
        "has_vuln": has_vuln_rows,
        "user": user_rows,
        "account": account_rows,
        "membership": membership_rows,
        "group": group_rows,
        "admin_to": admin_to_rows,
        "connects_to": connects_to_rows,
        "auth": auth_rows,
        "alert": alert_rows,
    }


def load(driver, rows: dict) -> None:
    run(driver, ASSET_QUERY, rows=rows["asset"])
    run(driver, NETWORK_QUERY, rows=rows["network"])
    run(driver, IN_NETWORK_QUERY, rows=rows["in_network"])
    run(driver, SERVICE_QUERY, rows=rows["service"])
    run(driver, RUNS_QUERY, rows=rows["service"])
    run(driver, VULN_QUERY, rows=rows["vuln"])
    run(driver, HAS_VULN_QUERY, rows=rows["has_vuln"])
    run(driver, USER_QUERY, rows=rows["user"])
    run(driver, ACCOUNT_QUERY, rows=rows["account"])
    run(driver, HAS_ACCOUNT_QUERY, rows=rows["account"])
    run(driver, GROUP_QUERY, rows=rows["group"])
    run(driver, MEMBER_OF_QUERY, rows=rows["membership"])
    run(driver, ADMIN_TO_QUERY, rows=rows["admin_to"])
    run(driver, CONNECTS_TO_QUERY, rows=rows["connects_to"])
    run(driver, AUTHENTICATED_TO_QUERY, rows=rows["auth"])
    run(driver, ALERT_QUERY, rows=rows["alert"])


def delete_stale_derived_edges(driver, rows: dict) -> None:
    """Xóa CONNECTS_TO/ADMIN_TO/HAS_VULN(rule) không còn khớp $rows hiện tại — 3 quan
    hệ này suy diễn từ bảng rule viết tay, đổi rule mà không xóa cạnh cũ sẽ để lại
    dương tính giả trên attack path graph (xem Fix round 1, major #5)."""
    connects_pairs = [[r["src"], r["dst"]] for r in rows["connects_to"]]
    run(driver, DELETE_STALE_CONNECTS_TO_QUERY, pairs=connects_pairs)

    admin_pairs = [[r["group"], r["asset_canonical_id"]] for r in rows["admin_to"]]
    run(driver, DELETE_STALE_ADMIN_TO_QUERY, pairs=admin_pairs)

    has_vuln_pairs = [[r["service_id"], r["cve"]] for r in rows["has_vuln"]]
    run(driver, DELETE_STALE_HAS_VULN_QUERY, pairs=has_vuln_pairs)


def verify_counts(driver) -> bool:
    node_rows, _, _ = run(
        driver,
        "MATCH (n) WHERE NOT n:LoadMeta RETURN labels(n)[0] AS label, count(*) AS n ORDER BY label",
    )
    node_counts = {r["label"]: r["n"] for r in node_rows}
    rel_rows, _, _ = run(
        driver, "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n ORDER BY type"
    )
    rel_counts = {r["type"]: r["n"] for r in rel_rows}

    ok = True
    print("Node:")
    for label, expect in EXPECT_NODES.items():
        actual = node_counts.get(label, 0)
        good = actual == expect
        ok = ok and good
        print(
            ("  OK   " if good else "  FAIL ") + f"{label}: {actual} (kỳ vọng {expect})"
        )
    print("Relationship:")
    for rtype, expect in EXPECT_RELS.items():
        actual = rel_counts.get(rtype, 0)
        good = actual == expect
        ok = ok and good
        print(
            ("  OK   " if good else "  FAIL ") + f"{rtype}: {actual} (kỳ vọng {expect})"
        )
    return ok


def warn_stale(driver, crosswalk: dict) -> None:
    valid_ids = set(crosswalk.values())
    for label, prop in (("Asset", "canonical_id"), ("User", "canonical_id")):
        rows, _, _ = run(driver, f"MATCH (n:{label}) RETURN n.{prop} AS cid")
        db_ids = {r["cid"] for r in rows if r["cid"] is not None}
        stale = db_ids - valid_ids
        if stale:
            print(
                f"CẢNH BÁO: {label} có canonical_id không còn trong crosswalk hiện tại: {sorted(stale)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Nạp dữ liệu pipeline Giai đoạn 02 vào Neo4j (Schema v2)."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Xóa sạch toy graph Giai đoạn 01 (đã xác nhận với Chinh) trước khi nạp.",
    )
    args = parser.parse_args()

    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print(f"Đã kết nối {URI}")

        # Đọc + dựng rows TRƯỚC khi --reset (minor fix round 1): nếu input hỏng/thiếu,
        # dừng ở đây — không xóa DB mà không nạp lại được gì.
        try:
            data = load_inputs()
            rows = build_all_rows(data)
        except Exception as exc:  # noqa: BLE001 — lỗi đọc/dựng input bất kỳ đều phải dừng trước khi đụng DB
            print(
                f"LỖI: không đọc/dựng được dữ liệu nguồn ({exc}). Không ghi gì xuống DB."
            )
            return 2

        if not args.reset:
            n_blocked = guard_blocked(driver)
            stored_hash = get_stored_crosswalk_hash(driver)
            current_hash = crosswalk_hash(data["crosswalk"])
            hash_changed = stored_hash is not None and stored_hash != current_hash

            if n_blocked > 0:
                print(
                    f"BLOCKED: tìm thấy {n_blocked} Asset/User thiếu canonical_id "
                    "(có thể là toy graph Giai đoạn 01 cũ). Không ghi gì xuống DB.\n"
                    "Xác nhận với Chinh rồi chạy lại với --reset để xóa và nạp dữ liệu pipeline thật."
                )
                return 2
            if hash_changed:
                print(
                    "BLOCKED: crosswalk.json đã đổi từ lần nạp trước (hash lệch) — entity "
                    "resolution có thể đã chạy lại và dịch số canonical_id (xem Fix round 1, "
                    "major #4). Không ghi gì xuống DB.\n"
                    "Xác nhận với Chinh rồi chạy lại với --reset để nạp lại từ đầu."
                )
                return 2
            if stored_hash is None:
                # Fix round 2, minor "bootstrap hash guard": chưa từng lưu hash (vd DB
                # nạp bằng code trước Fix round 1/major #4) nhưng đã có Asset thật ->
                # không thể xác nhận canonical_id hiện tại còn khớp crosswalk.json hay
                # không -> coi như nghi vấn giống hash lệch, chặn luôn cho an toàn.
                existing_asset_rows, _, _ = run(driver, ASSET_COUNT_QUERY)
                if existing_asset_rows[0]["n"] > 0:
                    print(
                        "BLOCKED: DB đã có Asset nhưng chưa từng lưu crosswalk_hash (có thể "
                        "nạp từ code cũ trước Fix round 1). Không thể xác nhận canonical_id "
                        "hiện có còn khớp crosswalk.json hiện tại. Không ghi gì xuống DB.\n"
                        "Xác nhận với Chinh rồi chạy lại với --reset để nạp lại từ đầu."
                    )
                    return 2
        else:
            print(
                "Đang --reset: xóa toy graph cũ (kể cả GDS projection attack/attack_u nếu còn)..."
            )
            reset(driver)

        create_constraints(driver)

        load(driver, rows)
        delete_stale_derived_edges(driver, rows)
        save_crosswalk_hash(driver, data["crosswalk"])

        ok = verify_counts(driver)
        warn_stale(driver, data["crosswalk"])

        if not ok:
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())
