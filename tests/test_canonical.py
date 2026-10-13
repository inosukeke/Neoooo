"""Unit test cho src/ingestion/canonical.py — dùng dữ liệu thật trong src/ingestion/."""

import json
import os
import re

from canonical import (
    alert_id,
    asset_canonical_id,
    event_meta,
    load_crosswalk,
    user_canonical_id,
)

INGESTION_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "ingestion")
)
ALERTS_PATH = os.path.join(INGESTION_DIR, "normalized", "alerts.json")

ALERT_ID_RE = re.compile(r"^AL-(\d{8}-)?[0-9a-f]{12}$")


def load_alerts():
    with open(ALERTS_PATH, encoding="utf-8") as f:
        return json.load(f)


def test_alert_id_deterministic():
    alerts = load_alerts()
    a = alerts[0]
    assert alert_id(a) == alert_id(a)


def test_alert_id_unique_and_well_formed():
    alerts = load_alerts()
    ids = [alert_id(a) for a in alerts]
    assert len(ids) == 30
    assert len(set(ids)) == 30
    for i in ids:
        assert ALERT_ID_RE.match(i)


def test_alert_id_has_date_prefix_when_iso_time_present():
    """Format mới AL-{YYYYMMDD}-{12_char_sha1} giúp sort theo ngày dễ — chỉ áp
    dụng khi `time` ISO format chuẩn (≥10 ký tự)."""
    alerts = load_alerts()
    a = alerts[0]
    aid = alert_id(a)
    # ISO time đầu tiên là "2026-10-05..." -> prefix "20261005"
    assert aid.startswith("AL-20261005-"), aid


def test_asset_canonical_id_covers_all_alert_computers():
    cw = load_crosswalk()
    alerts = load_alerts()
    computers = {a["computer"] for a in alerts}
    for c in computers:
        assert asset_canonical_id(cw, "log", c) is not None, c


def test_asset_canonical_id_unknown_key_returns_none():
    cw = load_crosswalk()
    assert asset_canonical_id(cw, "log", "khong-ton-tai-999") is None


def test_user_canonical_id_covers_all_alert_target_users():
    cw = load_crosswalk()
    alerts = load_alerts()
    users = {a["target_user"] for a in alerts if a.get("target_user")}
    for u in users:
        assert user_canonical_id(cw, "idp", u) is not None, u


def test_event_meta_known_and_unknown():
    assert event_meta(4625) == ("low", "Failed logon (4625)")
    assert event_meta(4624) == ("info", "Successful logon (4624)")
    severity, rule = event_meta(9999)
    assert severity == "info"
    assert rule == "Event 9999"
