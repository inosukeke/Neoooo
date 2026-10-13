"""Unit test cho src/graph/graph_rows.py — dùng dữ liệu thật trong src/ingestion/."""

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


def _data():
    return load_inputs()


def test_asset_rows_count_and_keys():
    d = _data()
    rows = build_asset_rows(d["assets"], d["crosswalk"], d["review_queue"])
    assert len(rows) == 26
    cids = [r["canonical_id"] for r in rows]
    assert len(cids) == len(set(cids))
    hostnames = [r["hostname"] for r in rows]
    assert len(hostnames) == len(set(hostnames))


def test_asset_rows_in_review_and_ip():
    d = _data()
    rows = build_asset_rows(d["assets"], d["crosswalk"], d["review_queue"])
    assert sum(1 for r in rows if r["in_review"]) == 8
    assert sum(1 for r in rows if r["ip"] is not None) == 21


# --- Hostname priority theo ASSET_SOURCE_PRIORITY = ("nmap", "log", "ad") ---
# Xem graph_rows.py:25. Edge case: cluster chỉ có 1 nguồn (log/ad), hoặc nhiều
# nguồn không có nmap → hostname lấy từ nguồn ưu tiên cao nhất có mặt.


def _build_rows_for_priority_test():
    """Crossfeed giả — 4 cluster demo 4 case hostname priority."""
    return {
        "nmap:10.0.1.50": "ast-test-1",  # cluster chỉ có nmap
        "log:ws-foo": "ast-test-2",  # cluster chỉ có log
        "ad:WEB-BAR": "ast-test-3",  # cluster chỉ có ad (phải normalize)
        "log:web-02": "ast-test-4",  # cluster log+ad, hostname từ log (priority > ad)
        "ad:WEB-02": "ast-test-4",  # (cùng cluster 4)
    }


def _norm_assets():
    return [
        {"source": "nmap", "source_id": "10.0.1.50", "ip": "10.0.1.50", "hostname": "web-extra"},
        {"source": "log", "source_id": "ws-foo", "ip": None, "hostname": "ws-foo"},
        {"source": "ad", "source_id": "WEB-BAR", "ip": None, "hostname": "WEB-BAR.LAB.LOCAL"},
        {"source": "log", "source_id": "web-02", "ip": None, "hostname": "web-02"},
        {"source": "ad", "source_id": "WEB-02", "ip": None, "hostname": "WEB-02"},
    ]


def test_asset_rows_hostname_priority_nmap_only():
    cw = _build_rows_for_priority_test()
    rows = build_asset_rows(_norm_assets(), cw, [])
    by_cid = {r["canonical_id"]: r for r in rows}
    assert by_cid["ast-test-1"]["hostname"] == "web-extra"
    assert by_cid["ast-test-1"]["ip"] == "10.0.1.50"


def test_asset_rows_hostname_priority_log_only():
    cw = _build_rows_for_priority_test()
    rows = build_asset_rows(_norm_assets(), cw, [])
    by_cid = {r["canonical_id"]: r for r in rows}
    assert by_cid["ast-test-2"]["hostname"] == "ws-foo"
    assert by_cid["ast-test-2"]["ip"] is None


def test_asset_rows_hostname_priority_ad_only_normalized():
    """Cluster chỉ có AD (uppercase FQDN) → hostname phải qua `normalize_name` để
    cắt FQDN và lowercase."""
    cw = _build_rows_for_priority_test()
    rows = build_asset_rows(_norm_assets(), cw, [])
    by_cid = {r["canonical_id"]: r for r in rows}
    assert by_cid["ast-test-3"]["hostname"] == "web-bar"


def test_asset_rows_hostname_priority_log_beats_ad():
    """Cluster log + ad (không có nmap): hostname lấy từ log (priority > ad),
    không qua normalize_name vì không phải ad."""
    cw = _build_rows_for_priority_test()
    rows = build_asset_rows(_norm_assets(), cw, [])
    by_cid = {r["canonical_id"]: r for r in rows}
    assert by_cid["ast-test-4"]["hostname"] == "web-02"


def test_user_rows_count():
    d = _data()
    rows = build_user_rows(d["users"], d["crosswalk"])
    assert len(rows) == 17
    cids = [r["canonical_id"] for r in rows]
    assert len(cids) == len(set(cids))


def test_service_rows_count_and_id_shape():
    d = _data()
    rows = build_service_rows(d["services"], d["crosswalk"])
    assert len(rows) == 33
    for r in rows:
        assert r["id"] == f"{r['asset_canonical_id']}:{r['port']}/{r['protocol']}"


def test_vuln_rows_count_and_kev_bool():
    d = _data()
    rows = build_vuln_rows(d["vulnerabilities"])
    assert len(rows) == 28
    assert all(isinstance(r["kev"], bool) for r in rows)


def test_account_rows_count():
    d = _data()
    rows = build_account_rows(d["accounts"], d["crosswalk"])
    assert len(rows) == 16


def test_membership_rows_count():
    d = _data()
    rows = build_membership_rows(d["memberships"])
    assert len(rows) == 21


def test_alert_rows_count():
    d = _data()
    rows = build_alert_rows(d["alerts"], d["crosswalk"])
    assert len(rows) == 30


def test_auth_rows_count():
    """Số cặp (account, asset) khác nhau có >=1 lần logon thành công (4624) trong
    30 alert — đo được là 22 (không phải giả định 22 trong brief, đây là số thật)."""
    d = _data()
    rows = build_auth_rows(d["alerts"], d["crosswalk"])
    assert len(rows) == 22
    pairs = [(r["account"], r["asset_canonical_id"]) for r in rows]
    assert len(pairs) == len(set(pairs))
