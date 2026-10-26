"""Test module risk_scoring — chỉ logic thuần + driver giả, không cần service."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import risk_scoring as rs


def _score(**kw):
    base = {
        "cvss": 10.0,
        "epss": 1.0,
        "in_kev": False,
        "asset_criticality": 5,
        "reachable": True,
    }
    base.update(kw)
    return rs.compute_risk_score(**base)


def test_max_inputs_give_one():
    assert _score() == 1.0


def test_unreachable_zeroes_risk():
    assert _score(reachable=False) == 0.0


def test_cvss_zero_zeroes_risk():
    assert _score(cvss=0.0, in_kev=True) == 0.0


def test_epss_zero_zeroes_risk_when_not_kev():
    assert _score(epss=0.0) == 0.0


def test_kev_forces_likelihood_one():
    assert _score(
        cvss=5.0, epss=0.01, in_kev=True, asset_criticality=5
    ) == pytest.approx(0.5)
    assert _score(
        cvss=5.0, epss=0.01, in_kev=False, asset_criticality=5
    ) == pytest.approx(0.005)


def test_formula_multiplicative():
    assert _score(cvss=8.0, epss=0.5, asset_criticality=3) == pytest.approx(
        0.8 * 0.5 * 0.6
    )


@pytest.mark.parametrize(
    "kw",
    [
        {"cvss": -0.1},
        {"cvss": 10.1},
        {"epss": -0.1},
        {"epss": 1.1},
        {"asset_criticality": 0},
        {"asset_criticality": 6},
    ],
)
def test_invalid_input_raises(kw):
    with pytest.raises(ValueError):
        _score(**kw)


def test_risk_to_cost_bounds():
    assert rs.risk_to_cost(1.0) == 1.0
    assert rs.risk_to_cost(0.0) == 10.0
    assert rs.risk_to_cost(0.5) == pytest.approx(5.5)
    with pytest.raises(ValueError):
        rs.risk_to_cost(1.5)


def test_patch_priority_uses_max():
    assert rs.patch_priority(0.9, 2) == 0.9
    assert rs.patch_priority(0.1, 5) == 1.0
    assert rs.patch_priority(0.3, 3) == pytest.approx(0.6)
    with pytest.raises(ValueError):
        rs.patch_priority(1.2, 3)


def test_compute_reachable_bfs():
    edges = [("a", "b"), ("b", "c"), ("x", "y")]
    assert rs.compute_reachable({"a"}, edges) == {"a", "b", "c"}
    assert rs.compute_reachable(set(), edges) == set()


def test_score_assets_ranking_and_unreachable():
    assets = [
        {
            "canonical_id": "A",
            "hostname": "web-01",
            "asset_criticality": 3,
            "vulns": [{"cve": "CVE-1", "cvss": 9.0, "epss": 0.1, "kev": False}],
        },
        {
            "canonical_id": "B",
            "hostname": "dc-01",
            "asset_criticality": 5,
            "vulns": [
                {"cve": "CVE-2", "cvss": 10.0, "epss": 0.0, "kev": True},
                {"cve": "CVE-3", "cvss": 3.0, "epss": 0.1, "kev": False},
            ],
        },
        {
            "canonical_id": "C",
            "hostname": "db-01",
            "asset_criticality": 5,
            "vulns": [{"cve": "CVE-2", "cvss": 10.0, "epss": 0.0, "kev": True}],
        },
        {"canonical_id": "D", "hostname": "ws-01", "asset_criticality": 2, "vulns": []},
    ]
    risks = rs.score_assets(assets, {"A", "B"})
    by_id = {r.canonical_id: r for r in risks}
    assert risks[0].canonical_id == "B"
    assert by_id["B"].risk_score == 1.0 and by_id["B"].cost == 1.0
    assert by_id["B"].drivers["top_cve"] == "CVE-2" and by_id["B"].drivers["in_kev"]
    assert by_id["C"].risk_score == 0.0 and by_id["C"].cost == 10.0  # không reachable
    assert by_id["D"].risk_score == 0.0
    assert by_id["D"].patch_priority == pytest.approx(0.4)


def test_build_edge_costs_uses_dst_cost():
    risks = [rs.AssetRisk("B", "dc", 1.0, 1.0, 1.0, {})]
    out = rs.build_edge_costs([("A", "B"), ("A", "Z")], risks)
    assert out == [
        {"src": "A", "dst": "B", "cost": 1.0},
        {"src": "A", "dst": "Z", "cost": 10.0},
    ]


def test_business_context_tables():
    assert rs.criticality_for("dc-01") == 5
    assert rs.criticality_for("zzz-99") == rs.DEFAULT_CRITICALITY
    assert rs.exposure_for("web-01") == "public"
    assert rs.exposure_for("db-01") == "internal"
    assert all(1 <= v <= 5 for v in rs.CRITICALITY_BY_ROLE.values())


# ---------- Runner với driver giả ----------
class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def consume(self):
        return None


class _Rec:
    def __init__(self, d):
        self._d = d

    def data(self):
        return self._d


class _FakeSession:
    def __init__(self, driver):
        self.driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.driver.calls.append((query, params))
        return _FakeResult([_Rec(r) for r in self.driver.responses.get(query, [])])


class _FakeDriver:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def session(self):
        return _FakeSession(self)


def _fake_driver():
    return _FakeDriver(
        {
            "MATCH (a:Asset) RETURN a.canonical_id AS canonical_id, a.hostname AS hostname": [
                {"canonical_id": "A", "hostname": "web-01"},
                {"canonical_id": "B", "hostname": "dc-01"},
            ],
            rs.READ_ASSETS_QUERY: [
                {
                    "canonical_id": "A",
                    "hostname": "web-01",
                    "asset_criticality": 3,
                    "vulns": [],
                },
                {
                    "canonical_id": "B",
                    "hostname": "dc-01",
                    "asset_criticality": 5,
                    "vulns": [
                        {"cve": "CVE-2", "cvss": 10.0, "epss": 0.5, "kev": True},
                        None,
                    ],
                },
            ],
            rs.READ_ENTRY_POINTS_QUERY: [{"canonical_id": "A"}],
            rs.READ_EDGES_QUERY: [{"src": "A", "dst": "B"}],
        }
    )


def test_runner_writes_cost_parameterized():
    drv = _fake_driver()
    risks = rs.run_risk_scoring(drv)
    assert risks[0].canonical_id == "B" and risks[0].risk_score == 1.0
    writes = [c for c in drv.calls if c[0] == rs.WRITE_COST_QUERY]
    assert writes[0][1]["rows"] == [{"src": "A", "dst": "B", "cost": 1.0}]
    # mọi query phải là hằng số, giá trị đi qua tham số
    assert any(q == rs.SET_ASSET_CRITICALITY_QUERY for q, _ in drv.calls)
    assert any(q == rs.SET_SERVICE_EXPOSURE_QUERY for q, _ in drv.calls)


def test_runner_dry_run_does_not_write_cost():
    drv = _fake_driver()
    rs.run_risk_scoring(drv, write=False)
    assert not any(q == rs.WRITE_COST_QUERY for q, _ in drv.calls)


def test_runner_idempotent_same_result_twice():
    a = rs.run_risk_scoring(_fake_driver())
    b = rs.run_risk_scoring(_fake_driver())
    assert a == b


# ---------- Nhánh bổ sung ----------
def test_score_assets_uses_pagerank_value():
    assets = [
        {"canonical_id": "A", "hostname": "ws-01", "asset_criticality": 2, "vulns": []}
    ]
    (r,) = rs.score_assets(assets, set(), {"A": 0.9})
    assert r.patch_priority == pytest.approx(0.9)  # max(0.9, 0.4)


def test_score_assets_skips_vuln_missing_cvss_and_epss_none_is_zero():
    assets = [
        {
            "canonical_id": "A",
            "hostname": "web-01",
            "asset_criticality": 5,
            "vulns": [
                {"cve": "CVE-NOCVSS", "cvss": None, "epss": 1.0, "kev": True},
                {"cve": "CVE-NOEPSS", "cvss": 9.0, "epss": None, "kev": False},
            ],
        }
    ]
    (r,) = rs.score_assets(assets, {"A"})
    assert r.risk_score == 0.0  # epss None -> 0, vuln thiếu cvss bị bỏ
    assert r.drivers["top_cve"] == "CVE-NOEPSS"


def test_score_assets_criticality_none_falls_back_to_table():
    assets = [
        {
            "canonical_id": "A",
            "hostname": "dc-01",
            "asset_criticality": None,
            "vulns": [{"cve": "CVE-1", "cvss": 10.0, "epss": 1.0, "kev": False}],
        }
    ]
    (r,) = rs.score_assets(assets, {"A"})
    assert r.drivers["asset_criticality"] == 5
    assert r.risk_score == 1.0


def test_score_assets_dirty_vuln_is_skipped_not_crash():
    assets = [
        {
            "canonical_id": "A",
            "hostname": "web-01",
            "asset_criticality": 5,
            "vulns": [
                {"cve": "CVE-BAD", "cvss": 99.0, "epss": 0.5, "kev": False},
                {"cve": "CVE-OK", "cvss": 5.0, "epss": 1.0, "kev": False},
            ],
        }
    ]
    (r,) = rs.score_assets(assets, {"A"})
    assert r.drivers["top_cve"] == "CVE-OK"
    assert r.risk_score == pytest.approx(0.5)


def test_top_cve_tiebreak_deterministic():
    v1 = {"cve": "CVE-B", "cvss": 8.0, "epss": 0.5, "kev": False}
    v2 = {"cve": "CVE-A", "cvss": 8.0, "epss": 0.5, "kev": False}
    for order in ([v1, v2], [v2, v1]):
        assets = [
            {
                "canonical_id": "A",
                "hostname": "web-01",
                "asset_criticality": 5,
                "vulns": order,
            }
        ]
        (r,) = rs.score_assets(assets, {"A"})
        assert r.drivers["top_cve"] == "CVE-A"


def test_format_ranking_output():
    risks = [
        rs.AssetRisk(
            "A",
            "dc-01",
            1.0,
            1.0,
            1.0,
            {"top_cve": "CVE-1", "in_kev": True, "reachable": True},
        ),
        rs.AssetRisk(
            "B",
            "ws-01",
            0.0,
            10.0,
            0.4,
            {"top_cve": None, "in_kev": False, "reachable": False},
        ),
    ]
    out = rs.format_ranking(risks, top=5)
    assert "CVE-1 [KEV]" in out and "[unreachable]" in out
    assert len(out.splitlines()) == 3
    assert len(rs.format_ranking(risks, top=1).splitlines()) == 2


def test_context_queries_do_not_overwrite_manual_values():
    assert "coalesce(a.asset_criticality" in rs.SET_ASSET_CRITICALITY_QUERY
    assert "coalesce(s.exposure" in rs.SET_SERVICE_EXPOSURE_QUERY


def test_cli_import_works_with_isolated_sys_path(tmp_path):
    """Regression: chạy trực tiếp script không có src/graph trên sys.path vẫn import được graph_rules."""
    script = Path(rs.__file__).resolve()
    code = (
        "import runpy,sys; "
        f"m = runpy.run_path({str(script)!r}); "
        "print(m['asset_role_of']('dc-01'))"
    )
    proc = subprocess.run(
        [sys.executable, "-E", "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        cwd=tmp_path,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "dc"


@pytest.mark.integration
def test_integration_run_twice_idempotent_on_real_neo4j():
    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    pw = os.environ.get("NEO4J_PASSWORD")
    auth = (os.environ.get("NEO4J_USER", "neo4j"), pw) if pw else None
    count_q = "MATCH ()-[r:CONNECTS_TO]->() RETURN count(r) AS n, min(r.cost) AS lo, max(r.cost) AS hi"
    with GraphDatabase.driver(uri, auth=auth) as driver:
        rs.run_risk_scoring(driver)
        n1 = driver.execute_query(count_q).records[0].data()
        rs.run_risk_scoring(driver)
        n2 = driver.execute_query(count_q).records[0].data()
    assert n1["n"] == n2["n"] > 0
    assert 1.0 <= n2["lo"] <= n2["hi"] <= 10.0
