"""Unit test cho src/ingestion/resolution/entity_resolution.py — dùng dữ liệu
thật trong src/ingestion/normalized/."""

from entity_resolution import (
    asset_score,
    build_crosswalk,
    cluster,
    decide,
    load_norm,
    load_truth,
    normalize_name,
    records_from,
    scored_pairs,
    user_score,
    username_variants,
)


def _records_asset():
    return records_from(load_norm("assets"), "hostname")


def _records_user():
    return records_from(load_norm("users"), "username")


def _exact_score(a, b):
    return 100.0 if a == b else 0.0


# ---------- normalize_name ----------
def test_normalize_name_lowercases_and_trims_fqdn():
    """FQDN `db-01.LAB.LOCAL` -> cắt theo `.` đầu tiên sau @ -> `db-01`."""
    assert normalize_name("db-01.LAB.LOCAL") == "db-01"
    assert normalize_name("DB-01") == "db-01"
    assert normalize_name("web-01.lab.local") == "web-01"


def test_normalize_name_handles_email_prefix():
    """`user@lab.local` -> cắt @ trước, rồi cắt `.` -> lấy phần đầu."""
    assert normalize_name("an.nguyen@lab.local") == "an"


# ---------- username_variants ----------
def test_username_variants_3_variants():
    v = username_variants("an.nguyen0")
    # base, no-dot, swap first/last
    assert "an.nguyen0" in v
    assert "annguyen0" in v
    assert "nguyen0.an" in v


# ---------- scored_pairs ----------
def test_scored_pairs_dedup_pairs():
    """A->B và B->A nên xuất hiện 1 lần với score cao nhất."""
    records = [
        {"id": ("nmap", "1.1.1.1"), "name": "web-01", "source": "nmap"},
        {"id": ("log", "web-01"), "name": "web-01", "source": "log"},
    ]
    pairs = scored_pairs(records, _exact_score)
    # 2 record, mỗi cái so với record khác: 2 pairs dedup thành 1
    assert len(pairs) == 1
    assert pairs[0]["score"] == 100.0


# ---------- build_crosswalk deterministic ----------
def test_build_crosswalk_deterministic_across_runs():
    """Chạy build_crosswalk 5 lần trên cùng input (asset_score thật) -> output y hệt
    và đúng 26 canonical."""
    records = _records_asset()
    pairs = decide(scored_pairs(records, asset_score))
    clusters = cluster(records, pairs)

    cw_first = build_crosswalk(clusters, "asset")
    cw_list = [dict(sorted(build_crosswalk(clusters, "asset").items())) for _ in range(5)]
    for cw in cw_list[1:]:
        assert cw == cw_list[0]
    # 26 unique canonical ids
    assert len(set(cw_first.values())) == 26


def test_build_crosswalk_no_dict_key_repr_dependency():
    """Verify không phụ thuộc repr/hash của UnionFind root (là tuple).

    Bug cũ: `str(kv[0])` cho tuple sort theo Python repr, có thể thay đođổi
    giữa các phiên bản/hash. Sort key mới `min(ids)` chỉ so sánh tuple `(source,
    raw)` — deterministic."""
    clusters = {
        ("B", "B"): [("nmap", "z"), ("ad", "Z")],
        ("A", "A"): [("nmap", "a"), ("ad", "A")],
    }
    cw = build_crosswalk(clusters, "asset")
    # Cluster có min(ids) = ('ad', 'A') -> sort trước
    assert cw["ad:A"] == "asset-000"
    assert cw["nmap:a"] == "asset-000"
    # Cluster có min(ids) = ('ad', 'Z') -> sort sau
    assert cw["ad:Z"] == "asset-001"
    assert cw["nmap:z"] == "asset-001"


# ---------- pipeline E2E nhẹ trên data thật ----------
def test_asset_pipeline_produces_expected_crosswalk_size():
    """Trên 55 asset normalized, ER ra đúng 26 canonical_id."""
    records = _records_asset()
    pairs = decide(scored_pairs(records, asset_score))
    clusters = cluster(records, pairs)
    cw = build_crosswalk(clusters, "asset")
    assert len(set(cw.values())) == 26
    assert len(cw) == 55


def test_user_pipeline_produces_expected_crosswalk_size():
    records = _records_user()
    pairs = decide(scored_pairs(records, user_score))
    clusters = cluster(records, pairs)
    cw = build_crosswalk(clusters, "user")
    assert len(set(cw.values())) == 17
    assert len(cw) == 31


def test_eval_against_ground_truth_asset_th95():
    """Eval P/R/F1 ở ngưỡng 95 phải giữ P=1.0 (không có false merge)."""
    records = _records_asset()
    pairs = decide(scored_pairs(records, asset_score))
    cluster(records, pairs)
    # Không dùng crosswalk ở đây — đánh giá trực tiếp trên predict pairs.

    truth = load_truth()[0]
    # Thay vì đếm match qua canonical, đếm qua predict pairs thuộc threshold 95
    predicted = [
        frozenset((p["a"][0] + ":" + p["a"][1], p["b"][0] + ":" + p["b"][1]))
        for p in pairs
        if p["score"] >= 95
    ]
    predicted_set = set(predicted)
    tp = len(predicted_set & truth)
    fp = len(predicted_set - truth)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    assert precision == 1.0