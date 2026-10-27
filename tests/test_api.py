"""Unit test cho FastAPI app (src/api/main.py).

Mock `main.run_text2cypher`/`main.run_graphrag`/`main.get_health` qua
monkeypatch — không gọi Neo4j/LLM thật, theo đúng convention
`tests/test_text2cypher.py`.
"""

from fastapi.testclient import TestClient

from secgraph.api import main
from secgraph.llm.graphrag.graphrag_demo import GraphRAGResult
from secgraph.llm.text2cypher.text2cypher import Text2CypherResult

client = TestClient(main.app)


def test_health_ok(monkeypatch):
    fake_health = {
        "neo4j": {"connected": True, "uri": "bolt://localhost:7687", "error": None},
        "vector_index": {
            "name": "vuln_description_embedding",
            "state": "ONLINE",
            "error": None,
        },
        "model_chain": ["gpt-5-nano", "gpt-4o-mini"],
        "graph_summary": {"asset_count": 26, "user_count": 17},
        "read_only": True,
        "checked_at": "2026-10-27T00:00:00+00:00",
    }
    monkeypatch.setattr(main, "get_health", lambda: fake_health)

    resp = client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["neo4j"]["connected"] is True
    assert body["vector_index"]["name"] == "vuln_description_embedding"
    assert body["graph_summary"]["asset_count"] == 26
    assert body["read_only"] is True


def test_overview_ok(monkeypatch):
    fake_overview = {
        "neo4j": {"connected": True, "uri": "bolt://localhost:7687", "error": None},
        "vector_index": {
            "name": "vuln_description_embedding",
            "state": "ONLINE",
            "error": None,
        },
        "model_chain": ["gpt-5-nano", "gpt-4o-mini"],
        "graph_summary": {"asset_count": 26, "user_count": 17},
        "read_only": True,
        "checked_at": "2026-10-27T00:00:00+00:00",
        "counts": {
            "asset_count": 26,
            "user_count": 17,
            "vulnerability_count": 28,
            "vulnerability_kev_count": 28,
            "service_count": 33,
            "account_count": 16,
            "group_count": 5,
            "alert_count": 30,
        },
    }
    monkeypatch.setattr(main, "get_overview", lambda: fake_overview)

    resp = client.get("/overview")

    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["asset_count"] == 26
    assert body["counts"]["vulnerability_kev_count"] == 28
    assert body["counts"]["alert_count"] == 30
    assert body["read_only"] is True


def test_risk_ok(monkeypatch):
    fake_risk = {
        "items": [
            {
                "canonical_id": "ast-004",
                "hostname": "dc-01",
                "risk_score": 0.88,
                "cost": 2.08,
                "patch_priority": 1.0,
                "drivers": {
                    "asset_criticality": 5,
                    "reachable": True,
                    "vuln_count": 2,
                    "top_cve": "CVE-2017-0144",
                    "cvss": 9.8,
                    "epss": 0.9,
                    "in_kev": True,
                },
            },
            {
                "canonical_id": "ast-002",
                "hostname": "db-01",
                "risk_score": 0.0,
                "cost": 10.0,
                "patch_priority": 1.0,
                "drivers": {
                    "asset_criticality": 5,
                    "reachable": False,
                    "vuln_count": 0,
                    "top_cve": None,
                    "cvss": None,
                    "epss": None,
                    "in_kev": False,
                },
            },
        ],
        "summary": {
            "scored_asset_count": 2,
            "high_risk_count": 1,
            "high_risk_threshold": 0.5,
            "avg_risk_score": 0.44,
            "pagerank_wired": False,
        },
    }
    monkeypatch.setattr(main, "get_risk_ranking", lambda: fake_risk)

    resp = client.get("/risk")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["canonical_id"] == "ast-004"
    assert body["items"][0]["drivers"]["top_cve"] == "CVE-2017-0144"
    assert body["summary"]["high_risk_count"] == 1
    assert body["summary"]["pagerank_wired"] is False


def test_risk_backend_error_returns_502(monkeypatch):
    def _boom():
        raise RuntimeError("Neo4j không kết nối được")

    monkeypatch.setattr(main, "get_risk_ranking", _boom)

    resp = client.get("/risk")

    assert resp.status_code == 502
    assert "Neo4j" in resp.json()["detail"]


def test_alerts_ok(monkeypatch):
    fake_alerts = {
        "total": 2,
        "hits": [
            {
                "alert_id": "AL-1",
                "time": "2026-10-05T10:59:00Z",
                "event_id": 4625,
                "success": False,
                "outcome": "failure",
                "severity": "low",
                "rule": "Failed logon (4625)",
                "message": "An account failed to log on.",
                "computer": "app-02",
                "asset_canonical_id": "ast-001",
            },
            {
                "alert_id": "AL-2",
                "time": "2026-10-05T11:00:00Z",
                "event_id": 4624,
                "success": True,
                "outcome": "success",
                "severity": "info",
                "rule": "Successful logon (4624)",
                "message": "An account was successfully logged on.",
                "computer": "dc-01",
                "asset_canonical_id": "ast-004",
            },
        ],
        "facets": {
            "asset": [{"key": "ast-001", "doc_count": 1}, {"key": "ast-004", "doc_count": 1}],
            "rule": [
                {"key": "Failed logon (4625)", "doc_count": 1},
                {"key": "Successful logon (4624)", "doc_count": 1},
            ],
            "success": [
                {"key": "false", "doc_count": 1},
                {"key": "true", "doc_count": 1},
            ],
        },
        "histogram": [{"date": "2026-10-05T00:00:00.000Z", "doc_count": 2}],
    }
    captured: dict = {}

    def fake_get_alerts(**kwargs):
        captured.update(kwargs)
        return fake_alerts

    monkeypatch.setattr(main, "get_alerts", fake_get_alerts)

    resp = client.get("/alerts", params={"success": "false", "size": 5, "from": 0})

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["hits"]) == 2
    assert body["facets"]["asset"][0]["key"] == "ast-001"
    assert body["histogram"][0]["doc_count"] == 2
    assert captured["success"] is False
    assert captured["size"] == 5
    assert captured["from_"] == 0


def test_alerts_backend_error_returns_502(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("OpenSearch không kết nối được")

    monkeypatch.setattr(main, "get_alerts", _boom)

    resp = client.get("/alerts")

    assert resp.status_code == 502
    assert "OpenSearch" in resp.json()["detail"]


def test_attack_path_ok(monkeypatch):
    fake_data = {
        "nodes": [
            {
                "canonical_id": "ast-010",
                "hostname": "mail-01",
                "asset_criticality": 3,
                "is_entry_point": True,
                "is_crown_jewel": False,
            },
            {
                "canonical_id": "ast-004",
                "hostname": "dc-01",
                "asset_criticality": 5,
                "is_entry_point": False,
                "is_crown_jewel": True,
            },
        ],
        "edges": [{"src": "ast-010", "dst": "ast-004", "cost": 2.08}],
        "entry_points": ["ast-010"],
        "crown_jewels": ["ast-004"],
        "paths": [
            {
                "source": "ast-010",
                "target": "ast-004",
                "total_cost": 2.08,
                "hops": ["ast-010", "ast-004"],
            }
        ],
        "choke_points": [
            {"canonical_id": "ast-000", "hostname": "app-01", "betweenness": 4.0}
        ],
        "path_frequency": [{"canonical_id": "ast-010", "count": 1}],
        "reachable": ["ast-010", "ast-004"],
        "min_criticality": 4,
    }
    captured: dict = {}

    def fake_get_attack_path(**kwargs):
        captured.update(kwargs)
        return fake_data

    monkeypatch.setattr(main, "get_attack_path", fake_get_attack_path)

    resp = client.get("/attack-path")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 2
    assert body["nodes"][0]["is_entry_point"] is True
    assert body["paths"][0]["total_cost"] == 2.08
    assert body["choke_points"][0]["canonical_id"] == "ast-000"
    assert captured["min_criticality"] == 4


def test_attack_path_custom_min_criticality(monkeypatch):
    captured: dict = {}

    def fake_get_attack_path(**kwargs):
        captured.update(kwargs)
        return {
            "nodes": [],
            "edges": [],
            "entry_points": [],
            "crown_jewels": [],
            "paths": [],
            "choke_points": [],
            "path_frequency": [],
            "reachable": [],
            "min_criticality": kwargs["min_criticality"],
        }

    monkeypatch.setattr(main, "get_attack_path", fake_get_attack_path)

    resp = client.get("/attack-path", params={"min_criticality": 5})

    assert resp.status_code == 200
    assert captured["min_criticality"] == 5
    assert resp.json()["min_criticality"] == 5


def test_attack_path_backend_error_returns_502(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("thiếu CONNECTS_TO.cost")

    monkeypatch.setattr(main, "get_attack_path", _boom)

    resp = client.get("/attack-path")

    assert resp.status_code == 502
    assert "cost" in resp.json()["detail"]


def test_ask_text2cypher_ok(monkeypatch):
    fake_result = Text2CypherResult(
        question="Máy nào chạy dịch vụ có lỗ hổng nằm trong KEV?",
        status="ok",
        cypher="MATCH (a:Asset) RETURN a.hostname AS hostname",
        attempts=1,
        fixes=[],
        rows=[{"hostname": "dc01"}],
        answer="Có 1 máy.",
        errors=[],
        prompt_tokens=10,
        completion_tokens=5,
        latency_ms=120,
        model="gpt-4o-mini",
    )
    monkeypatch.setattr(main, "run_text2cypher", lambda q: fake_result)

    resp = client.post("/ask", json={"pipeline": "text2cypher", "question": "x"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["pipeline"] == "text2cypher"
    assert body["status"] == "ok"
    assert body["rows"] == [{"hostname": "dc01"}]
    assert body["model"] == "gpt-4o-mini"


def test_ask_text2cypher_rejected_write(monkeypatch):
    fake_result = Text2CypherResult(
        question="Xóa tất cả node Asset",
        status="rejected_write",
        cypher="MATCH (a:Asset) DELETE a",
        attempts=1,
        fixes=[],
        rows=[],
        answer="Yêu cầu này cần quyền ghi, hệ thống chỉ cho phép đọc.",
        errors=[],
        prompt_tokens=8,
        completion_tokens=0,
        latency_ms=12,
        model="gpt-4o-mini",
    )
    monkeypatch.setattr(main, "run_text2cypher", lambda q: fake_result)

    resp = client.post(
        "/ask", json={"pipeline": "text2cypher", "question": "Xóa tất cả node Asset"}
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected_write"


def test_ask_graphrag_ok_with_sources_and_scores(monkeypatch):
    context = (
        '{"id": "CVE-2017-0144", "description": "EternalBlue", "cvss": 9.8, "kev": true}\n'
        '{"id": "CVE-2021-34527", "description": "PrintNightmare", "cvss": 8.8, "kev": true}'
    )
    fake_result = GraphRAGResult(
        question="Lỗ hổng SMB nguy hiểm nhất trên domain controller là gì?",
        answer="CVE-2017-0144 nguy hiểm nhất.",
        context=context,
        seed_ids=["CVE-2017-0144", "CVE-2021-34527"],
        latency_ms=800,
        prompt_tokens=200,
        completion_tokens=60,
        model="gpt-4o-mini",
    )
    seed_scores = {"CVE-2017-0144": 0.962, "CVE-2021-34527": 0.8}
    monkeypatch.setattr(main, "run_graphrag", lambda q: (fake_result, seed_scores))

    resp = client.post("/ask", json={"pipeline": "graphrag", "question": "x"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["pipeline"] == "graphrag"
    assert len(body["sources"]) == 2
    assert body["sources"][0]["id"] == "CVE-2017-0144"
    assert body["sources"][0]["score"] == 0.962
    assert body["sources"][0]["data"]["cvss"] == 9.8
    # record mở rộng không phải seed -> không có score bịa
    assert body["sources"][1]["score"] == 0.8


def test_ask_backend_error_returns_502(monkeypatch):
    def _boom(q):
        raise RuntimeError("Neo4j không kết nối được")

    monkeypatch.setattr(main, "run_text2cypher", _boom)

    resp = client.post("/ask", json={"pipeline": "text2cypher", "question": "x"})

    assert resp.status_code == 502
    assert "Neo4j" in resp.json()["detail"]


def test_ask_invalid_pipeline_returns_422():
    resp = client.post("/ask", json={"pipeline": "sql", "question": "x"})
    assert resp.status_code == 422


def test_ask_empty_question_returns_422():
    resp = client.post("/ask", json={"pipeline": "text2cypher", "question": ""})
    assert resp.status_code == 422
