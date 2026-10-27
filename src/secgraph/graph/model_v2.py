"""Giai đoạn 01 — Mô hình hóa dữ liệu an ninh: migrate schema v1 -> v2 + 8 câu hỏi kiểm.

Chạy lặp được (idempotent): MERGE theo khóa duy nhất, SET phần còn lại; bước DELETE
cạnh cũ dùng MATCH nên chạy lại vẫn an toàn (không thấy gì thì không lỗi).
Yêu cầu: đã chạy seed_graph.py (schema v1, 5 Asset) trước khi chạy file này.
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

SCHEMA = [
    "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE",
    "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
    "CREATE INDEX alert_time IF NOT EXISTS FOR (a:Alert) ON (a.time)",
]

STEPS = [
    (
        "user và account mới (dave)",
        """UNWIND $rows AS r
        MERGE (u:User {username: r.user}) SET u.dept = r.dept
        MERGE (c:Account {name: r.acct})
        MERGE (u)-[:HAS_ACCOUNT]->(c)""",
        {"rows": [{"user": "dave", "dept": "sysadmin", "acct": "dave.adm"}]},
    ),
    (
        "group và MEMBER_OF",
        """UNWIND $rows AS r
        MATCH (c:Account {name: r.acct})
        MERGE (g:Group {name: r.grp})
        MERGE (c)-[:MEMBER_OF]->(g)""",
        {"rows": [
            {"acct": "bob.adm", "grp": "DBA"},
            {"acct": "dave.adm", "grp": "Domain Admins"},
        ]},
    ),
    (
        "ADMIN_TO từ group",
        """UNWIND $rows AS r
        MATCH (g:Group {name: r.grp}), (a:Asset {hostname: r.host})
        MERGE (g)-[:ADMIN_TO]->(a)""",
        {"rows": [
            {"grp": "DBA", "host": "db-01"},
            {"grp": "Domain Admins", "host": "dc-01"},
        ]},
    ),
    (
        "bỏ CAN_ACCESS trực tiếp của bob.adm (đã có quyền qua nhóm DBA)",
        """MATCH (:Account {name: 'bob.adm'})-[r:CAN_ACCESS]->(:Asset {hostname: 'db-01'})
        DELETE r""",
        {},
    ),
    (
        "AUTHENTICATED_TO (đã quan sát)",
        """UNWIND $rows AS r
        MATCH (c:Account {name: r.acct}), (a:Asset {hostname: r.host})
        MERGE (c)-[x:AUTHENTICATED_TO]->(a)
          SET x.last_seen = datetime(r.last_seen)""",
        {"rows": [
            {"acct": "carol.hr", "host": "ws-hr-01", "last_seen": "2026-10-05T07:50:00Z"},
            {"acct": "dave.adm", "host": "app-01", "last_seen": "2026-10-05T01:35:00Z"},
        ]},
    ),
    (
        "OWNS",
        """UNWIND $rows AS r
        MATCH (u:User {username: r.user}), (a:Asset {hostname: r.host})
        MERGE (u)-[:OWNS]->(a)""",
        {"rows": [
            {"user": "bob", "host": "db-01"},
            {"user": "dave", "host": "app-01"},
            {"user": "dave", "host": "dc-01"},
            {"user": "carol", "host": "ws-hr-01"},
        ]},
    ),
    (
        "property trên HAS_VULN",
        """MATCH (:Service)-[r:HAS_VULN]->(:Vulnerability)
        SET r.first_seen = coalesce(r.first_seen, datetime('2026-09-20T00:00:00Z')),
            r.status = coalesce(r.status, 'open')""",
        {},
    ),
    (
        "Alert",
        """UNWIND $rows AS r
        MATCH (a:Asset {hostname: r.host})
        MERGE (al:Alert {id: r.id})
          SET al.time = datetime(r.time), al.severity = r.severity, al.rule = r.rule
        MERGE (al)-[:TRIGGERED_ON]->(a)
        WITH al, r
        OPTIONAL MATCH (c:Account {name: r.acct})
        FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END |
          MERGE (al)-[:INVOLVES]->(c))""",
        {"rows": [
            {"id": "AL-001", "time": "2026-10-05T01:12:00Z", "severity": "high",
             "rule": "Log4Shell exploit attempt", "host": "app-01", "acct": None},
            {"id": "AL-002", "time": "2026-10-05T01:40:00Z", "severity": "medium",
             "rule": "Admin logon to app server", "host": "app-01", "acct": "dave.adm"},
            {"id": "AL-003", "time": "2026-10-05T07:55:00Z", "severity": "low",
             "rule": "Failed logon burst", "host": "ws-hr-01", "acct": "carol.hr"},
        ]},
    ),
]

REACH = """
MATCH p = (u:User)-[:HAS_ACCOUNT|MEMBER_OF|ADMIN_TO|CAN_ACCESS|CONNECTS_TO*1..{n}]->(:Asset {{hostname: $target}})
RETURN u.username AS username, min(length(p)) AS hops
ORDER BY hops, username
"""

QUESTIONS = [
    (
        "1. chủ máy có lỗ hổng KEV",
        """MATCH (u:User)-[:OWNS]->(a:Asset)-[:RUNS]->(:Service)-[:HAS_VULN]->(v:Vulnerability {kev: true})
        RETURN u.username AS owner, a.hostname AS host, collect(DISTINCT v.cve) AS cves
        ORDER BY host""",
        {},
    ),
    (
        "2. admin của db-01 (trực tiếp hoặc qua nhóm)",
        """MATCH (u:User)-[:HAS_ACCOUNT]->(:Account)-[:MEMBER_OF*0..1]->(x)-[:ADMIN_TO]->(:Asset {hostname: 'db-01'})
        RETURN DISTINCT u.username AS username""",
        {},
    ),
    (
        "3. phiên admin còn lưu trên máy nào",
        """MATCH (u:User)-[:HAS_ACCOUNT]->(acct:Account)-[:AUTHENTICATED_TO]->(a:Asset)
        WHERE EXISTS { (acct)-[:MEMBER_OF]->(:Group)-[:ADMIN_TO]->(:Asset) }
        RETURN u.username AS username, a.hostname AS host""",
        {},
    ),
    (
        "4. alert ngày 2026-10-05 trên máy có lỗ hổng KEV",
        """MATCH (al:Alert)-[:TRIGGERED_ON]->(a:Asset)
        WHERE EXISTS { (a)-[:RUNS]->(:Service)-[:HAS_VULN]->(:Vulnerability {kev: true}) }
          AND al.time >= datetime('2026-10-05T00:00:00Z')
          AND al.time <  datetime('2026-10-06T00:00:00Z')
        RETURN al.id AS alert, a.hostname AS host ORDER BY al.time""",
        {},
    ),
    (
        "6. app-01 bị chiếm thì lộ gì",
        """MATCH (a:Asset {hostname: 'app-01'})<-[:AUTHENTICATED_TO]-(acct:Account)
              -[:MEMBER_OF]->(g:Group)-[:ADMIN_TO]->(t:Asset)
        RETURN acct.name AS account, g.name AS grp, t.hostname AS opens""",
        {},
    ),
    (
        "7. từ web-01 đi tới đâu (CONNECTS_TO, tối đa 3 bước)",
        """MATCH p = (:Asset {hostname: 'web-01'})-[:CONNECTS_TO*1..3]->(t:Asset)
        RETURN t.hostname AS host, min(length(p)) AS hops ORDER BY hops, host""",
        {},
    ),
    (
        "8. số lỗ hổng open theo máy",
        """MATCH (a:Asset)-[:RUNS]->(:Service)-[r:HAS_VULN]->(:Vulnerability)
        WHERE r.status = 'open'
        RETURN a.hostname AS host, count(*) AS open_vulns
        ORDER BY open_vulns DESC, host""",
        {},
    ),
]

EXPECT_NODES = {
    "Account": 4, "Alert": 3, "Asset": 5, "Group": 2, "Network": 3,
    "Service": 4, "User": 4, "Vulnerability": 3,
}
EXPECT_RELS = {
    "ADMIN_TO": 2, "AUTHENTICATED_TO": 2, "CAN_ACCESS": 2, "CONNECTS_TO": 4,
    "HAS_ACCOUNT": 4, "HAS_VULN": 3, "IN_NETWORK": 5, "INVOLVES": 2,
    "MEMBER_OF": 2, "OWNS": 4, "RUNS": 4, "TRIGGERED_ON": 3,
}


def run(driver, query, **params):
    return driver.execute_query(query, database_="neo4j", **params)


def show(title, records):
    print(f"\n{title}")
    for r in records:
        print("  ", r.data())


def who_reaches(driver, target, max_hops):
    # Cận *1..N không truyền bằng parameter được — chỉ chèn số nguyên đã ép kiểu int().
    query = REACH.format(n=int(max_hops))
    records, _, _ = run(driver, query, target=target)
    return records


def main():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print(f"Đã kết nối {URI}")

        records, _, _ = run(driver, "MATCH (a:Asset) RETURN count(a) AS n")
        if records[0]["n"] != 5:
            sys.exit("Chưa thấy 5 Asset của schema v1 — chạy src/graph/seed_graph.py trước.")

        for query in SCHEMA:
            run(driver, query)
        for name, query, params in STEPS:
            run(driver, query, **params)
            print("xong:", name)

        for title, query, params in QUESTIONS:
            records, _, _ = run(driver, query, **params)
            show(title, records)

        for n in (3, 5):
            show(f"5. tới db-01 trong tối đa {n} bước", who_reaches(driver, "db-01", n))

        node_rows, _, _ = run(driver, "MATCH (n) RETURN labels(n)[0] AS k, count(*) AS n")
        rel_rows, _, _ = run(driver, "MATCH ()-[r]->() RETURN type(r) AS k, count(*) AS n")
        node_counts = {r["k"]: r["n"] for r in node_rows}
        rel_counts = {r["k"]: r["n"] for r in rel_rows}

        print("\nNode:", "OK" if node_counts == EXPECT_NODES else f"LỆCH {node_counts}")
        print("Relationship:", "OK" if rel_counts == EXPECT_RELS else f"LỆCH {rel_counts}")


if __name__ == "__main__":
    main()
