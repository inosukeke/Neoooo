"""Test attack_path.py — fake driver, không cần Neo4j/GDS (trừ test integration)."""

import os

import attack_path as ap
import pytest


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
        resp = self.driver.responses.get(query, [])
        if callable(resp):
            resp = resp(params)
        return [_Rec(r) for r in resp]


class _FakeDriver:
    """responses: query -> list[dict] hoặc callable(params) -> list[dict]."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def session(self):
        return _FakeSession(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _gds_base(**extra):
    r = {
        ap.MISSING_COST_QUERY: [{"missing": 0}],
        ap.GRAPH_EXISTS_QUERY: [{"exists": False}],
        ap.PROJECTED_NODES_QUERY: [
            {"canonical_id": c}
            for c in ("e", "e1", "e2", "c", "c1", "c2", "m", "a", "b")
        ],
        ap.PROJECT_FULL_QUERY: [{"nodes": 4, "rels": 3}],
        ap.PROJECT_SUB_QUERY: [{"nodes": 3, "rels": 2}],
    }
    r.update(extra)
    return r


def test_find_entry_points_filters_public():
    d = _FakeDriver(
        {ap.ENTRY_POINTS_QUERY: [{"canonical_id": "a1"}, {"canonical_id": "a2"}]}
    )
    assert ap.find_entry_points(d) == ["a1", "a2"]
    assert d.calls[0][1] == {"exposure": "public"}
    assert "$exposure" in ap.ENTRY_POINTS_QUERY


def test_find_crown_jewels_threshold_param():
    d = _FakeDriver({ap.CROWN_JEWELS_QUERY: [{"canonical_id": "db"}]})
    assert ap.find_crown_jewels(d) == ["db"]
    assert d.calls[0][1] == {"min_criticality": 4}
    ap.find_crown_jewels(d, min_criticality=5)
    assert d.calls[1][1] == {"min_criticality": 5}


def test_rank_attack_paths_cost_then_tiebreak():
    p = [
        ap.AttackPath("b", "z", 3.0, ["b", "z"]),
        ap.AttackPath("a", "z", 3.0, ["a", "z"]),
        ap.AttackPath("c", "y", 1.5, ["c", "y"]),
        ap.AttackPath("a", "y", 3.0, ["a", "y"]),
    ]
    ranked = ap.rank_attack_paths(p)
    assert [(x.source, x.target) for x in ranked] == [
        ("c", "y"),
        ("a", "y"),
        ("a", "z"),
        ("b", "z"),
    ]
    assert ap.rank_attack_paths(list(reversed(p))) == ranked


def test_shortest_attack_paths_builds_and_ranks():
    def dijkstra(params):
        table = {
            ("e1", "c1"): [{"totalCost": 7.0, "path": ["e1", "m", "c1"]}],
            ("e1", "c2"): [],  # không có đường
            ("e2", "c1"): [{"totalCost": 2.0, "path": ["e2", "c1"]}],
        }
        return table.get((params["src"], params["dst"]), [])

    d = _FakeDriver(_gds_base(**{ap.DIJKSTRA_QUERY: dijkstra}))
    paths = ap.shortest_attack_paths(d, ["e1", "e2"], ["c1", "c2"])
    assert [(p.source, p.target, p.total_cost) for p in paths] == [
        ("e2", "c1", 2.0),
        ("e1", "c1", 7.0),
    ]
    assert paths[1].hops == ["e1", "m", "c1"]
    # drop-nếu-tồn-tại: exists=False -> không drop; project trước khi chạy Dijkstra
    queries = [q for q, _ in d.calls]
    assert ap.GRAPH_DROP_QUERY not in queries
    assert queries.index(ap.PROJECT_FULL_QUERY) < queries.index(ap.DIJKSTRA_QUERY)


def test_entry_equal_crown_yields_zero_cost_self_path():
    d = _FakeDriver(_gds_base(**{ap.DIJKSTRA_QUERY: []}))
    paths = ap.shortest_attack_paths(d, ["x"], ["x"])
    assert paths == [ap.AttackPath("x", "x", 0.0, ["x"])]
    assert not any(q == ap.DIJKSTRA_QUERY for q, _ in d.calls)
    assert ap.shortest_attack_paths(d, [], ["x"]) == []


def test_entry_crown_outside_projection_are_skipped_not_dijkstra():
    # "iso" không có cạnh CONNECTS_TO -> không nằm trong bản chiếu: không gọi GDS cho nó.
    d = _FakeDriver(
        _gds_base(
            **{
                ap.DIJKSTRA_QUERY: [{"totalCost": 1.0, "path": ["e", "c"]}],
                ap.PROJECTED_NODES_QUERY: [
                    {"canonical_id": "e"},
                    {"canonical_id": "c"},
                ],
            }
        )
    )
    paths = ap.shortest_attack_paths(d, ["e", "iso"], ["c", "iso2"])
    assert [(p.source, p.target) for p in paths] == [("e", "c")]
    called = [(p["src"], p["dst"]) for q, p in d.calls if q == ap.DIJKSTRA_QUERY]
    assert called == [("e", "c")]


def test_reachable_skips_entry_outside_projection():
    d = _FakeDriver(
        _gds_base(
            **{
                ap.BFS_QUERY: [{"reached": ["e", "a"]}],
                ap.PROJECTED_NODES_QUERY: [{"canonical_id": "e"}],
            }
        )
    )
    assert ap.reachable_from_entries(d, ["e", "iso"]) == {"e", "a", "iso"}
    srcs = [p["src"] for q, p in d.calls if q == ap.BFS_QUERY]
    assert srcs == ["e"]


def test_empty_projection_guard():
    d = _FakeDriver(_gds_base(**{ap.PROJECT_FULL_QUERY: [{"nodes": 0, "rels": 0}]}))
    assert ap.shortest_attack_paths(d, ["e"], ["c"]) == []
    assert ap.choke_points(d) == []


def test_path_frequency_counts_nodes_desc():
    paths = [
        ap.AttackPath("e1", "c", 1.0, ["e1", "m", "c"]),
        ap.AttackPath("e2", "c", 2.0, ["e2", "m", "c"]),
        ap.AttackPath("e1", "d", 3.0, ["e1", "d"]),
    ]
    assert ap.path_frequency(paths) == [
        ("c", 2),
        ("e1", 2),
        ("m", 2),
        ("d", 1),
        ("e2", 1),
    ]
    assert ap.path_frequency([]) == []


def test_missing_cost_raises_clear_error():
    d = _FakeDriver(_gds_base(**{ap.MISSING_COST_QUERY: [{"missing": 3}]}))
    with pytest.raises(ap.MissingCostError, match="3 cạnh.*không hợp lệ.*risk_scoring"):
        ap.shortest_attack_paths(d, ["e"], ["c"])
    assert not any(q == ap.PROJECT_FULL_QUERY for q, _ in d.calls)


def test_reprojection_drops_existing_graph():
    d = _FakeDriver(
        _gds_base(**{ap.GRAPH_EXISTS_QUERY: [{"exists": True}], ap.BFS_QUERY: []})
    )
    ap.reachable_from_entries(d, ["e"])
    queries = [q for q, _ in d.calls]
    assert queries.index(ap.GRAPH_DROP_QUERY) < queries.index(ap.PROJECT_FULL_QUERY)


def test_reachable_from_entries_unions_bfs():
    def bfs(params):
        return {
            "e1": [{"reached": ["e1", "a"]}],
            "e2": [{"reached": ["e2", "a", "b"]}],
        }[params["src"]]

    d = _FakeDriver(_gds_base(**{ap.BFS_QUERY: bfs}))
    assert ap.reachable_from_entries(d, ["e1", "e2"]) == {"e1", "e2", "a", "b"}


def test_reachable_with_max_depth_uses_depth_query():
    d = _FakeDriver(_gds_base(**{ap.BFS_DEPTH_QUERY: [{"reached": ["e"]}]}))
    assert ap.reachable_from_entries(d, ["e"], max_depth=2) == {"e"}
    assert d.calls[-1][1]["max_depth"] == 2
    assert ap.reachable_from_entries(d, []) == set()


def test_choke_points_sorted_descending_deterministic():
    rows = [
        {"hostname": "h-b", "canonical_id": "b", "score": 1.0},
        {"hostname": "h-a", "canonical_id": "a", "score": 1.0},
        {"hostname": "h-c", "canonical_id": "c", "score": 5.0},
        {"hostname": "h-d", "canonical_id": "d", "score": 0.0},
    ]
    d = _FakeDriver(_gds_base(**{ap.BETWEENNESS_QUERY: rows}))
    cps = ap.choke_points(d, subgraph_nodes={"a", "b", "c", "d"})
    assert [c.canonical_id for c in cps] == ["c", "a", "b", "d"]
    assert cps[0] == ap.ChokePoint("h-c", "c", 5.0)
    proj = next(p for q, p in d.calls if q == ap.PROJECT_SUB_QUERY)
    assert proj["ids"] == ["a", "b", "c", "d"]


def test_choke_points_empty_subgraph_and_full_graph():
    d = _FakeDriver(_gds_base(**{ap.BETWEENNESS_QUERY: []}))
    assert ap.choke_points(d, subgraph_nodes=set()) == []
    assert ap.choke_points(d) == []
    assert any(q == ap.PROJECT_FULL_QUERY for q, _ in d.calls)


def test_queries_are_module_constants_with_params_no_interpolation():
    import inspect

    queries = {
        k: v for k, v in vars(ap).items() if k.endswith("_QUERY") and isinstance(v, str)
    }
    assert len(queries) >= 10
    for q in (
        ap.DIJKSTRA_QUERY,
        ap.BFS_QUERY,
        ap.PROJECT_SUB_QUERY,
        ap.CROWN_JEWELS_QUERY,
    ):
        assert "$" in q
    # Không f-string dựng Cypher: mọi lời gọi _read/session.run chỉ truyền hằng *_QUERY.
    src = inspect.getsource(ap)
    assert 'f"MATCH' not in src and 'f"CALL' not in src and 'f"""' not in src


def test_cost_validation_query_catches_negative_and_wrong_type():
    q = ap.MISSING_COST_QUERY
    assert "IS NULL" in q and "< 0" in q and "IS :: FLOAT" in q


def test_run_attack_path_end_to_end_fake():
    d = _FakeDriver(
        _gds_base(
            **{
                ap.ENTRY_POINTS_QUERY: [{"canonical_id": "e"}],
                ap.CROWN_JEWELS_QUERY: [{"canonical_id": "c"}],
                ap.DIJKSTRA_QUERY: [{"totalCost": 4.0, "path": ["e", "m", "c"]}],
                ap.BETWEENNESS_QUERY: [
                    {"hostname": "m", "canonical_id": "m", "score": 1.0},
                    {"hostname": "e", "canonical_id": "e", "score": 0.0},
                ],
            }
        )
    )
    paths, chokes, freq, reachable = ap.run_attack_path(d)
    assert paths[0].hops == ["e", "m", "c"]
    assert chokes[0].canonical_id == "m"
    assert dict(freq)["m"] == 1
    assert "e" in reachable
    assert "e -> m -> c" in ap.format_paths(paths)
    assert "m" in ap.format_choke_points(chokes)


def test_run_attack_path_drops_projections_even_on_error():
    d = _FakeDriver(
        _gds_base(
            **{
                ap.ENTRY_POINTS_QUERY: [{"canonical_id": "e"}],
                ap.CROWN_JEWELS_QUERY: [{"canonical_id": "c"}],
                ap.MISSING_COST_QUERY: [{"missing": 1}],
                ap.GRAPH_EXISTS_QUERY: [{"exists": True}],
            }
        )
    )
    with pytest.raises(ap.MissingCostError):
        ap.run_attack_path(d)
    names = [p["name"] for q, p in d.calls if q == ap.GRAPH_DROP_QUERY]
    assert len(names) == 2
    assert names[0].startswith(ap.GRAPH_FULL + "_")
    assert names[1].startswith(ap.GRAPH_SUB + "_")


def test_run_attack_path_uses_unique_graph_names():
    d = _FakeDriver(_gds_base())
    ap.run_attack_path(d)
    ap.run_attack_path(d)
    names = {p["name"] for q, p in d.calls if q == ap.GRAPH_EXISTS_QUERY}
    assert len(names) == 4  # 2 lần chạy x (full, sub), không trùng tên


def test_main_exit_1_when_cost_missing(monkeypatch, capsys):
    import neo4j

    d = _FakeDriver(
        _gds_base(
            **{
                ap.ENTRY_POINTS_QUERY: [{"canonical_id": "e"}],
                ap.CROWN_JEWELS_QUERY: [{"canonical_id": "c"}],
                ap.MISSING_COST_QUERY: [{"missing": 2}],
            }
        )
    )
    monkeypatch.setattr(neo4j.GraphDatabase, "driver", lambda *a, **k: d)
    assert ap.main([]) == 1
    assert "risk_scoring" in capsys.readouterr().err


def test_main_prints_tables(monkeypatch, capsys):
    import neo4j

    d = _FakeDriver(
        _gds_base(
            **{
                ap.ENTRY_POINTS_QUERY: [{"canonical_id": "e"}],
                ap.CROWN_JEWELS_QUERY: [{"canonical_id": "c"}],
                ap.DIJKSTRA_QUERY: [{"totalCost": 4.0, "path": ["e", "m", "c"]}],
                ap.BETWEENNESS_QUERY: [
                    {"hostname": "m", "canonical_id": "m", "score": 1.0}
                ],
            }
        )
    )
    monkeypatch.setattr(neo4j.GraphDatabase, "driver", lambda *a, **k: d)
    assert ap.main(["--top", "5"]) == 0
    out = capsys.readouterr().out
    assert "e -> m -> c" in out and "reachable" in out and "số path" in out


@pytest.mark.integration
def test_integration_gds_real():
    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    pw = os.environ.get("NEO4J_PASSWORD")
    auth = (os.environ.get("NEO4J_USER", "neo4j"), pw) if pw else None
    with GraphDatabase.driver(uri, auth=auth) as driver:
        # Cần risk_scoring.py đã chạy (cost + exposure + asset_criticality).
        r1 = ap.run_attack_path(driver)
        r2 = ap.run_attack_path(driver)  # idempotent: chạy lại cho cùng kết quả
        paths, chokes, freq, reachable = r1
        assert paths, "cần ít nhất 1 attack path (đã chạy risk_scoring.py chưa?)"
        assert [(p.source, p.target, p.total_cost, p.hops) for p in paths] == [
            (p.source, p.target, p.total_cost, p.hops) for p in r2[0]
        ]
        costs = [p.total_cost for p in paths]
        assert costs == sorted(costs) and all(c >= 0 for c in costs)
        for p in paths:
            assert p.hops[0] == p.source and p.hops[-1] == p.target
        scores = [c.betweenness for c in chokes]
        assert chokes and scores == sorted(scores, reverse=True)
        assert freq and reachable
