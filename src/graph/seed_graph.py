"""Giai đoạn 01 — Neo4j & Cypher: nạp schema v1 + dữ liệu mẫu, xác minh số liệu và cú pháp đường đi.

Chạy lặp được (idempotent): MERGE theo khóa duy nhất đã có constraint, SET phần còn lại.
Yêu cầu: Neo4j 5.26 Community đang chạy (xem README.md), NEO4J_URI/USER/PASSWORD trong .env.
"""
import os
import sys

from neo4j import GraphDatabase

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
USER = os.getenv("NEO4J_USER", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD")
# Demo local: cho phép Neo4j không đặt mật khẩu (NEO4J_AUTH=none) — khi đó auth=None.
AUTH = (USER, PASSWORD) if PASSWORD else None

CONSTRAINTS = [
    "CREATE CONSTRAINT asset_hostname IF NOT EXISTS FOR (a:Asset) REQUIRE a.hostname IS UNIQUE",
    "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE",
    "CREATE CONSTRAINT user_username IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
    "CREATE CONSTRAINT account_name IF NOT EXISTS FOR (c:Account) REQUIRE c.name IS UNIQUE",
    "CREATE CONSTRAINT network_cidr IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE",
]

ASSETS = [
    {"hostname": "web-01", "ip": "10.0.1.10", "role": "web", "criticality": 3, "net": "10.0.1.0/24"},
    {"hostname": "app-01", "ip": "10.0.3.20", "role": "app", "criticality": 4, "net": "10.0.3.0/24"},
    {"hostname": "db-01", "ip": "10.0.3.30", "role": "db", "criticality": 5, "net": "10.0.3.0/24"},
    {"hostname": "dc-01", "ip": "10.0.3.5", "role": "dc", "criticality": 5, "net": "10.0.3.0/24"},
    {"hostname": "ws-hr-01", "ip": "10.0.2.15", "role": "workstation", "criticality": 2, "net": "10.0.2.0/24"},
]
SERVICES = [
    {"host": "web-01", "port": 443, "name": "nginx", "ver": "1.18.0"},
    {"host": "app-01", "port": 8080, "name": "tomcat", "ver": "9.0.50"},
    {"host": "db-01", "port": 5432, "name": "postgresql", "ver": "13.4"},
    {"host": "dc-01", "port": 445, "name": "smb", "ver": "SMBv1"},
]
VULNS = [
    {"cve": "CVE-2021-44228", "cvss": 10.0, "kev": True, "title": "Log4Shell"},
    {"cve": "CVE-2022-22965", "cvss": 9.8, "kev": True, "title": "Spring4Shell"},
    {"cve": "CVE-2017-0144", "cvss": 8.1, "kev": True, "title": "EternalBlue"},
]
VULN_LINKS = [
    {"svc": "app-01:8080", "cve": "CVE-2021-44228"},
    {"svc": "app-01:8080", "cve": "CVE-2022-22965"},
    {"svc": "dc-01:445", "cve": "CVE-2017-0144"},
]
FLOWS = [
    {"src": "web-01", "dst": "app-01", "port": 8080},
    {"src": "app-01", "dst": "db-01", "port": 5432},
    {"src": "ws-hr-01", "dst": "app-01", "port": 8080},
    {"src": "ws-hr-01", "dst": "dc-01", "port": 445},
]
USERS = [
    {"user": "alice", "dept": "contractor", "acct": "alice.ext", "host": "web-01"},
    {"user": "bob", "dept": "dba", "acct": "bob.adm", "host": "db-01"},
    {"user": "carol", "dept": "hr", "acct": "carol.hr", "host": "ws-hr-01"},
]

LOADS = [
    (
        """UNWIND $rows AS row
        MERGE (n:Network {cidr: row.net})
        MERGE (a:Asset {hostname: row.hostname})
          SET a.ip = row.ip, a.role = row.role, a.criticality = row.criticality
        MERGE (a)-[:IN_NETWORK]->(n)""",
        ASSETS,
    ),
    (
        """UNWIND $rows AS s
        MATCH (a:Asset {hostname: s.host})
        MERGE (svc:Service {id: s.host + ':' + toString(s.port)})
          SET svc.port = s.port, svc.name = s.name, svc.version = s.ver
        MERGE (a)-[:RUNS]->(svc)""",
        SERVICES,
    ),
    (
        """UNWIND $rows AS v
        MERGE (x:Vulnerability {cve: v.cve})
          SET x.cvss = v.cvss, x.kev = v.kev, x.title = v.title""",
        VULNS,
    ),
    (
        """UNWIND $rows AS l
        MATCH (s:Service {id: l.svc}), (v:Vulnerability {cve: l.cve})
        MERGE (s)-[:HAS_VULN]->(v)""",
        VULN_LINKS,
    ),
    (
        """UNWIND $rows AS f
        MATCH (a:Asset {hostname: f.src}), (b:Asset {hostname: f.dst})
        MERGE (a)-[:CONNECTS_TO {port: f.port}]->(b)""",
        FLOWS,
    ),
    (
        """UNWIND $rows AS r
        MATCH (a:Asset {hostname: r.host})
        MERGE (u:User {username: r.user}) SET u.dept = r.dept
        MERGE (c:Account {name: r.acct})
        MERGE (u)-[:HAS_ACCOUNT]->(c)
        MERGE (c)-[:CAN_ACCESS]->(a)""",
        USERS,
    ),
]

REACH = """
MATCH p = (u:User)-[:HAS_ACCOUNT|CAN_ACCESS|CONNECTS_TO*1..{n}]->(:Asset {{hostname: $target}})
RETURN u.username AS username, min(length(p)) AS hops
ORDER BY hops, username
"""

EXPECTED_NODE_COUNTS = {
    "Account": 3, "Asset": 5, "Network": 3, "Service": 4, "User": 3, "Vulnerability": 3,
}
EXPECTED_REL_COUNTS = {
    "CAN_ACCESS": 3, "CONNECTS_TO": 4, "HAS_ACCOUNT": 3, "HAS_VULN": 3, "IN_NETWORK": 5, "RUNS": 4,
}


def run(driver, query, **params):
    return driver.execute_query(query, database_="neo4j", **params)


def seed(driver):
    for constraint in CONSTRAINTS:
        run(driver, constraint)
    for query, rows in LOADS:
        run(driver, query, rows=rows)


def verify_counts(driver):
    node_rows, _, _ = run(driver, "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY label")
    node_counts = {r["label"]: r["n"] for r in node_rows}
    rel_rows, _, _ = run(driver, "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n ORDER BY type")
    rel_counts = {r["type"]: r["n"] for r in rel_rows}

    print("Node:", node_counts)
    print("Relationship:", rel_counts)

    node_ok = node_counts == EXPECTED_NODE_COUNTS
    rel_ok = rel_counts == EXPECTED_REL_COUNTS
    print(f"Node khớp mong đợi: {node_ok}")
    print(f"Relationship khớp mong đợi: {rel_ok}")
    return node_ok and rel_ok


def who_reaches(driver, target, max_hops):
    # Cận *1..N không truyền bằng parameter được (giới hạn cú pháp Cypher) — chỉ
    # chèn số nguyên đã ép kiểu int(), không bao giờ chèn chuỗi từ input ngoài.
    query = REACH.format(n=int(max_hops))
    records, _, _ = run(driver, query, target=target)
    return [(r["username"], r["hops"]) for r in records]


def test_advanced_paths(driver, target):
    """Xác minh hai cú pháp bài giảng đánh dấu 'chưa chạy thử trên Neo4j thật'."""
    results = {}

    try:
        records, _, _ = run(
            driver,
            """MATCH (u:User)-[:HAS_ACCOUNT]->(:Account)-[:CAN_ACCESS]->(entry:Asset)
                  -[:CONNECTS_TO]->{0,3}(:Asset {hostname: $target})
               RETURN DISTINCT u.username AS username, entry.hostname AS entry_point""",
            target=target,
        )
        results["quantified_relationship_{0,3}"] = ("OK", [(r["username"], r["entry_point"]) for r in records])
    except Exception as exc:  # noqa: BLE001 - probe tính năng Cypher: lỗi nào cũng ghi FAIL
        results["quantified_relationship_{0,3}"] = ("FAIL", str(exc))

    try:
        records, _, _ = run(
            driver,
            """MATCH (a:Asset {hostname: 'web-01'}), (b:Asset {hostname: $target})
               MATCH p = SHORTEST 1 (a)-[:CONNECTS_TO]->+(b)
               RETURN [n IN nodes(p) | n.hostname] AS duong_di""",
            target=target,
        )
        results["SHORTEST_1"] = ("OK", [r["duong_di"] for r in records])
    except Exception as exc:  # noqa: BLE001 - probe tính năng Cypher: lỗi nào cũng ghi FAIL
        results["SHORTEST_1"] = ("FAIL", str(exc))

    try:
        records, _, _ = run(
            driver,
            """MATCH (a:Asset {hostname: 'web-01'}), (b:Asset {hostname: $target})
               MATCH p = shortestPath((a)-[:CONNECTS_TO*..6]->(b))
               RETURN [n IN nodes(p) | n.hostname] AS duong_di, length(p) AS hops""",
            target=target,
        )
        results["shortestPath_legacy"] = ("OK", [(r["duong_di"], r["hops"]) for r in records])
    except Exception as exc:  # noqa: BLE001 - probe tính năng Cypher: lỗi nào cũng ghi FAIL
        results["shortestPath_legacy"] = ("FAIL", str(exc))

    return results


def profile_index_usage(driver):
    # Plan nằm trong summary.profile (cây operator), không phải trong records.
    _, summary, _ = run(driver, "PROFILE MATCH (a:Asset {hostname: 'db-01'}) RETURN a")

    operators = []

    def walk(plan):
        operators.append(plan.get("operatorType", "?"))
        for child in plan.get("children", []):
            walk(child)

    if summary.profile:
        walk(summary.profile)
    return operators


def main():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print(f"Đã kết nối {URI}")

        seed(driver)
        counts_ok = verify_counts(driver)

        for n in (3, 5):
            print(f"Tới db-01 trong tối đa {n} bước:", who_reaches(driver, "db-01", n))

        print("\nXác minh cú pháp còn nợ (quantified relationship, SHORTEST):")
        for name, (status, detail) in test_advanced_paths(driver, "db-01").items():
            print(f"  {name}: {status} — {detail}")

        print("\nKiểm PROFILE (kỳ vọng thấy NodeUniqueIndexSeek, không NodeByLabelScan):")
        for r in profile_index_usage(driver):
            print(" ", r)

        if not counts_ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
