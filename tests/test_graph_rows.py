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
