"""Unit + integration test cho src/graph/load_graph.py.

Unit (AC a — guard, major #4 hash guard): dùng driver/session GIẢ, không cần
Neo4j thật.
Integration (AC b-f — reset/load/idempotent/constraint/sanity, major #5 stale
derived edges): cần Neo4j thật đang chạy, gắn @pytest.mark.integration (skip bởi
pytest.ini addopts khi không có Neo4j — xem conftest.py: fixture neo4j_driver).

Fix round 1 / major #6: MỌI test gọi `--reset` hoặc ghi/xóa cạnh thật trên Neo4j
(không chỉ đọc) gắn thêm @_destructive — SKIP trừ khi export
ALLOW_DESTRUCTIVE_TESTS=1 (đã được Chinh cho phép xóa toy graph Giai đoạn 01 từ
đầu feature, nhưng người chạy integration test vẫn phải tự xác nhận bằng cờ này
trước khi test tự động --reset Neo4j thật). Chạy:
    ALLOW_DESTRUCTIVE_TESTS=1 python -m pytest tests/test_load_graph.py -v -m integration
"""

import os
import subprocess
import sys

import load_graph
import pytest
from load_graph import EXPECT_NODES, EXPECT_RELS, guard_blocked, main

_destructive = pytest.mark.skipif(
    os.environ.get("ALLOW_DESTRUCTIVE_TESTS") != "1",
    reason="test này chạy --reset / ghi-xóa dữ liệu Neo4j thật, cần export "
    "ALLOW_DESTRUCTIVE_TESTS=1 để xác nhận",
)


class _FakeRecord(dict):
    """Record giả — truy cập như dict (giống neo4j.Record r["n"])."""


class FakeDriver:
    """Driver giả mô phỏng driver.execute_query(query, database_=..., **params) ->
    (records, summary, keys). Ghi lại mọi câu Cypher đã gọi để kiểm tra không ghi
    gì xuống DB khi bị guard chặn."""

    def __init__(
        self,
        guard_asset_n: int,
        guard_user_n: int,
        stored_hash: str | None = None,
        asset_total_n: int = 0,
    ):
        self.guard_asset_n = guard_asset_n
        self.guard_user_n = guard_user_n
        self.stored_hash = stored_hash
        self.asset_total_n = asset_total_n
        self.queries: list[str] = []

    def verify_connectivity(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute_query(self, query, database_=None, **params):
        self.queries.append(query)
        if "WHERE a.canonical_id IS NULL" in query:
            return ([_FakeRecord(n=self.guard_asset_n)], None, None)
        if "WHERE u.canonical_id IS NULL" in query:
            return ([_FakeRecord(n=self.guard_user_n)], None, None)
        if "LoadMeta {key: 'crosswalk_hash'}" in query and "RETURN m.value" in query:
            if self.stored_hash is None:
                return ([], None, None)
            return ([_FakeRecord(v=self.stored_hash)], None, None)
        if query == "MATCH (a:Asset) RETURN count(a) AS n":
            return ([_FakeRecord(n=self.asset_total_n)], None, None)
        # Bất kỳ câu nào khác (constraint/MERGE/DETACH DELETE) không nên được gọi
        # trong kịch bản guard chặn — trả rỗng để phát hiện nếu lỡ gọi.
        return ([], None, None)


def test_guard_blocked_sums_asset_and_user_counts():
    fake = FakeDriver(guard_asset_n=5, guard_user_n=3)
    assert guard_blocked(fake) == 8


def test_guard_blocked_zero_when_clean():
    fake = FakeDriver(guard_asset_n=0, guard_user_n=0)
    assert guard_blocked(fake) == 0


def test_main_blocked_without_reset_writes_nothing(monkeypatch):
    """DB có Asset thiếu canonical_id (toy graph cũ) và KHÔNG --reset -> exit != 0,
    không gọi bất kỳ câu ghi (constraint/MERGE/DETACH DELETE) nào."""
    fake = FakeDriver(guard_asset_n=5, guard_user_n=0)
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    rc = main()

    assert rc != 0
    write_markers = (
        "DETACH DELETE",
        "CREATE CONSTRAINT",
        "CREATE INDEX",
        "MERGE (a:Asset {canonical_id",
    )
    assert not any(marker in q for q in fake.queries for marker in write_markers)


def test_main_blocked_user_only_without_reset(monkeypatch):
    """Guard cũng chặn khi chỉ User thiếu canonical_id (Asset sạch)."""
    fake = FakeDriver(guard_asset_n=0, guard_user_n=2)
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    rc = main()

    assert rc != 0


def test_main_not_blocked_when_clean(monkeypatch):
    """DB sạch (không Asset/User nào thiếu canonical_id, chưa có hash lưu) và
    KHÔNG --reset -> guard không chặn, luồng tiếp tục (create_constraints() đã
    được gọi)."""
    fake = FakeDriver(guard_asset_n=0, guard_user_n=0, stored_hash=None)
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    main()

    assert any("CREATE CONSTRAINT" in q for q in fake.queries)


def test_main_blocked_when_crosswalk_hash_mismatched(monkeypatch):
    """Major #4: crosswalk.json đổi (hash lệch) từ lần nạp trước và KHÔNG --reset
    -> exit != 0, không ghi gì xuống DB (entity resolution có thể đã dịch số
    canonical_id — xem crosswalk_hash() trong load_graph.py)."""
    from graph_rows import load_inputs

    real_crosswalk = load_inputs()["crosswalk"]
    stale_hash = load_graph.crosswalk_hash(real_crosswalk) + "stale"
    fake = FakeDriver(guard_asset_n=0, guard_user_n=0, stored_hash=stale_hash)
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    rc = main()

    assert rc != 0
    write_markers = (
        "DETACH DELETE",
        "CREATE CONSTRAINT",
        "MERGE (a:Asset {canonical_id",
    )
    assert not any(marker in q for q in fake.queries for marker in write_markers)


def test_main_not_blocked_when_crosswalk_hash_matches(monkeypatch):
    """Hash lưu KHỚP hash hiện tại -> không chặn vì lý do hash (vẫn tiếp tục nạp)."""
    from graph_rows import load_inputs

    real_crosswalk = load_inputs()["crosswalk"]
    matching_hash = load_graph.crosswalk_hash(real_crosswalk)
    fake = FakeDriver(guard_asset_n=0, guard_user_n=0, stored_hash=matching_hash)
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    main()

    assert any("CREATE CONSTRAINT" in q for q in fake.queries)


def test_main_blocked_when_no_stored_hash_but_assets_exist(monkeypatch):
    """Minor fix round 2 (bootstrap hash guard): DB đã có Asset nhưng chưa từng lưu
    crosswalk_hash (vd nạp bằng code trước Fix round 1/major #4) -> không thể xác
    nhận canonical_id hiện có còn khớp crosswalk.json hay không -> chặn giống hash
    lệch, không ghi gì xuống DB."""
    fake = FakeDriver(
        guard_asset_n=0, guard_user_n=0, stored_hash=None, asset_total_n=26
    )
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    rc = main()

    assert rc != 0
    write_markers = (
        "DETACH DELETE",
        "CREATE CONSTRAINT",
        "MERGE (a:Asset {canonical_id",
    )
    assert not any(marker in q for q in fake.queries for marker in write_markers)


def test_main_not_blocked_when_no_stored_hash_and_db_truly_empty(monkeypatch):
    """Bootstrap hợp lệ: DB trống hoàn toàn (asset_total_n=0, chưa có hash) -> không
    chặn, vẫn tiếp tục nạp lần đầu."""
    fake = FakeDriver(
        guard_asset_n=0, guard_user_n=0, stored_hash=None, asset_total_n=0
    )
    monkeypatch.setattr(load_graph.GraphDatabase, "driver", lambda *a, **kw: fake)
    monkeypatch.setattr(sys, "argv", ["load_graph.py"])

    main()

    assert any("CREATE CONSTRAINT" in q for q in fake.queries)


def test_crosswalk_hash_deterministic_and_sensitive_to_change():
    h1 = load_graph.crosswalk_hash({"a": "1", "b": "2"})
    h2 = load_graph.crosswalk_hash(
        {"b": "2", "a": "1"}
    )  # thứ tự key khác, nội dung giống
    h3 = load_graph.crosswalk_hash({"a": "1", "b": "9"})  # nội dung đổi
    assert h1 == h2
    assert h1 != h3


# ---------------------------------------------------------------------------
# Integration — cần Neo4j thật (bolt://localhost:7687, no-auth demo local).
# ---------------------------------------------------------------------------
LOAD_GRAPH_SCRIPT = load_graph.__file__


def _run_cli(*extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, LOAD_GRAPH_SCRIPT, *extra_args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _counts(driver):
    # LoadMeta là node kỹ thuật riêng của loader (hash crosswalk, không phải Schema
    # v2 nghiệp vụ) — loại khỏi so sánh với EXPECT_NODES, xem load_graph.verify_counts.
    node_rows, _, _ = driver.execute_query(
        "MATCH (n) WHERE NOT n:LoadMeta RETURN labels(n)[0] AS label, count(*) AS n",
        database_="neo4j",
    )
    rel_rows, _, _ = driver.execute_query(
        "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n", database_="neo4j"
    )
    nodes = {r["label"]: r["n"] for r in node_rows}
    rels = {r["type"]: r["n"] for r in rel_rows}
    return nodes, rels


@pytest.mark.integration
@_destructive
def test_reset_then_load_matches_expected_counts(neo4j_driver):
    result = _run_cli("--reset")
    assert result.returncode == 0, result.stdout + result.stderr

    nodes, rels = _counts(neo4j_driver)
    assert nodes == EXPECT_NODES
    assert rels == EXPECT_RELS


@pytest.mark.integration
def test_rerun_without_reset_is_idempotent(neo4j_driver):
    # Giả định DB đã ở trạng thái hợp lệ (đã --reset + load trước đó, cùng phiên
    # Neo4j thật — xem test_reset_then_load_matches_expected_counts). LƯU Ý (sửa lại
    # mô tả, Fix round 2 minor): test này KHÔNG chỉ đọc — _run_cli() thật sự ghi
    # (MERGE lại toàn bộ rows + delete_stale_derived_edges + save_crosswalk_hash),
    # chỉ là vô hại/idempotent khi DB đang ở trạng thái đúng.
    nodes_before, rels_before = _counts(neo4j_driver)

    result = _run_cli()
    assert result.returncode == 0, result.stdout + result.stderr

    nodes_after, rels_after = _counts(neo4j_driver)
    assert nodes_after == nodes_before
    assert rels_after == rels_before


@pytest.mark.integration
def test_constraints_include_canonical_id(neo4j_driver):
    records, _, _ = neo4j_driver.execute_query("SHOW CONSTRAINTS", database_="neo4j")
    names = {r["name"] for r in records}
    assert "asset_canonical_id" in names
    assert "user_canonical_id" in names


@pytest.mark.integration
def test_no_cost_property_on_connects_to(neo4j_driver):
    records, _, _ = neo4j_driver.execute_query(
        "MATCH ()-[r:CONNECTS_TO]->() WHERE r.cost IS NOT NULL RETURN count(r) AS n",
        database_="neo4j",
    )
    assert records[0]["n"] == 0


@pytest.mark.integration
def test_multi_hop_connects_to_path_exists(neo4j_driver):
    records, _, _ = neo4j_driver.execute_query(
        """MATCH (a:Asset), (b:Asset) WHERE a <> b
        WITH a, b LIMIT 50000
        MATCH p = (a)-[:CONNECTS_TO*2..3]->(b)
        RETURN count(p) AS n""",
        database_="neo4j",
    )
    assert records[0]["n"] > 0


@pytest.mark.integration
def test_kev_reachable_asset_count(neo4j_driver):
    """Số Asset có thể chạm tới 1 CVE kev=true qua RUNS->HAS_VULN — đo thật = 10
    (khớp brief T012); không ép nếu lệch, chỉ assert đúng số đã đo thật."""
    records, _, _ = neo4j_driver.execute_query(
        """MATCH (a:Asset)-[:RUNS]->(:Service)-[:HAS_VULN]->(v:Vulnerability {kev: true})
        RETURN count(DISTINCT a) AS n""",
        database_="neo4j",
    )
    assert records[0]["n"] == 10


def _rule_edge_count(driver, rule_id: str) -> int:
    records, _, _ = driver.execute_query(
        "MATCH ()-[r:CONNECTS_TO]->() WHERE $rule_id IN r.rules RETURN count(r) AS n",
        database_="neo4j",
        rule_id=rule_id,
    )
    return records[0]["n"]


@pytest.mark.integration
@_destructive
def test_delete_stale_connects_to_when_rule_removed(neo4j_driver, monkeypatch):
    """Major #5: bỏ 1 rule (R6) khỏi CONNECT_RULES, nạp lại KHÔNG --reset -> cạnh
    CONNECTS_TO cũ sinh từ R6 phải biến mất (không còn là dương tính giả trên
    attack path graph). Khôi phục đầy đủ graph ở cuối test (finally) để không ảnh
    hưởng các test integration khác chạy cùng phiên Neo4j thật."""
    import graph_rules as gr

    data = load_graph.load_inputs()

    # Baseline: nạp đầy đủ trước (đảm bảo R6 có mặt trước khi test xóa).
    rows_full = load_graph.build_all_rows(data)
    load_graph.load(neo4j_driver, rows_full)
    load_graph.delete_stale_derived_edges(neo4j_driver, rows_full)
    assert _rule_edge_count(neo4j_driver, "R6") > 0

    original_rules = gr.CONNECT_RULES
    try:
        monkeypatch.setattr(
            gr, "CONNECT_RULES", [r for r in original_rules if r["id"] != "R6"]
        )
        rows_without_r6 = load_graph.build_all_rows(data)
        load_graph.load(neo4j_driver, rows_without_r6)
        load_graph.delete_stale_derived_edges(neo4j_driver, rows_without_r6)

        assert _rule_edge_count(neo4j_driver, "R6") == 0
    finally:
        monkeypatch.setattr(gr, "CONNECT_RULES", original_rules)
        rows_restored = load_graph.build_all_rows(data)
        load_graph.load(neo4j_driver, rows_restored)
        load_graph.delete_stale_derived_edges(neo4j_driver, rows_restored)
        load_graph.save_crosswalk_hash(neo4j_driver, data["crosswalk"])

    assert _rule_edge_count(neo4j_driver, "R6") > 0


def _has_vuln_count_for_cve(driver, cve: str) -> int:
    records, _, _ = driver.execute_query(
        "MATCH ()-[r:HAS_VULN]->(v:Vulnerability {cve: $cve}) RETURN count(r) AS n",
        database_="neo4j",
        cve=cve,
    )
    return records[0]["n"]


@pytest.mark.integration
@_destructive
def test_delete_stale_has_vuln_when_rule_removed_entirely(neo4j_driver, monkeypatch):
    """Fix round 2, major mới: XÓA HẲN 1 rule (VMware vCenter -> CVE-2021-21972, CVE
    duy nhất của rule này trong dữ liệu thật — 1 cạnh HAS_VULN) khỏi
    CVE_SERVICE_RULES, nạp lại KHÔNG --reset -> cạnh HAS_VULN của CVE đó phải biến
    mất. Trước Fix round 2 (so theo tập CVE hiện tại), bug này sẽ KHÔNG xóa được
    cạnh vì CVE không còn nằm trong tập rule mới -> điều kiện IN $rule_cves sai với
    chính cạnh cần xóa. Code mới so theo CẶP (service, cve) + marker r.derived_by
    nên xóa đúng trong cả 2 trường hợp (đổi version HAY xóa hẳn rule). Khôi phục
    đầy đủ graph ở finally, xác nhận lại đúng 16 HAS_VULN/11 CVE sau cùng."""
    import graph_rules as gr

    target_cve = "CVE-2021-21972"
    data = load_graph.load_inputs()

    # Baseline: nạp đầy đủ trước (đảm bảo cạnh của rule vCenter có mặt trước khi xóa).
    rows_full = load_graph.build_all_rows(data)
    load_graph.load(neo4j_driver, rows_full)
    load_graph.delete_stale_derived_edges(neo4j_driver, rows_full)
    assert _has_vuln_count_for_cve(neo4j_driver, target_cve) == 1

    original_rules = gr.CVE_SERVICE_RULES
    try:
        monkeypatch.setattr(
            gr,
            "CVE_SERVICE_RULES",
            [r for r in original_rules if r["product"] != "VMware vCenter"],
        )
        rows_without_vcenter = load_graph.build_all_rows(data)
        load_graph.load(neo4j_driver, rows_without_vcenter)
        load_graph.delete_stale_derived_edges(neo4j_driver, rows_without_vcenter)

        assert _has_vuln_count_for_cve(neo4j_driver, target_cve) == 0
    finally:
        monkeypatch.setattr(gr, "CVE_SERVICE_RULES", original_rules)
        rows_restored = load_graph.build_all_rows(data)
        load_graph.load(neo4j_driver, rows_restored)
        load_graph.delete_stale_derived_edges(neo4j_driver, rows_restored)
        load_graph.save_crosswalk_hash(neo4j_driver, data["crosswalk"])

    records, _, _ = neo4j_driver.execute_query(
        "MATCH ()-[r:HAS_VULN]->() RETURN count(r) AS n", database_="neo4j"
    )
    assert records[0]["n"] == 16
    cve_records, _, _ = neo4j_driver.execute_query(
        "MATCH ()-[:HAS_VULN]->(v:Vulnerability) RETURN count(DISTINCT v) AS n",
        database_="neo4j",
    )
    assert cve_records[0]["n"] == 11
    assert _has_vuln_count_for_cve(neo4j_driver, target_cve) == 1
