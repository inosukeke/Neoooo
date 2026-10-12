"""Unit test cho src/search/index_alerts.py: nhân bản log alert + bulk index.

Test integration (OpenSearch thật) gắn @pytest.mark.integration, bị skip bởi
pytest.ini addopts (-m "not integration") khi không có OpenSearch chạy.
"""

from datetime import date

import pytest
from canonical import load_crosswalk
from index_alerts import expand_log_sample, index_alerts, load_alerts
from os_client import ALERTS_INDEX


def _alerts():
    return load_alerts()


def _cw():
    return load_crosswalk()


def test_expand_default_params_total_count():
    docs = expand_log_sample(_alerts(), _cw())
    assert len(docs) == 30 * 50 + 120 == 1620


def test_expand_ids_all_unique():
    docs = expand_log_sample(_alerts(), _cw())
    ids = [d["alert_id"] for d in docs]
    assert len(ids) == len(set(ids)) == 1620


def test_expand_deterministic():
    alerts = _alerts()
    cw = _cw()
    docs1 = expand_log_sample(alerts, cw)
    docs2 = expand_log_sample(alerts, cw)
    assert docs1 == docs2


def test_expand_exactly_30_synthetic_false():
    docs = expand_log_sample(_alerts(), _cw())
    originals = [d for d in docs if d["synthetic"] is False]
    assert len(originals) == 30
    ids = {d["alert_id"] for d in originals}
    orig_ids = {d["orig_alert_id"] for d in originals}
    assert ids == orig_ids


def test_expand_all_docs_have_asset_canonical_id():
    docs = expand_log_sample(_alerts(), _cw())
    for d in docs:
        assert d["asset_canonical_id"] is not None, d["alert_id"]


def test_expand_event_4625_count():
    docs = expand_log_sample(_alerts(), _cw())
    count_4625 = sum(1 for d in docs if d["event_id"] == 4625)
    # 7 alert gốc có event_id 4625 trong 30 record thật * 50 bản (gốc + 49
    # copy) = 350, cộng 120 doc burst (toàn bộ burst là 4625) = 470.
    print(f"so doc event_id=4625: {count_4625}")
    assert count_4625 == 470


def test_expand_all_docs_within_date_range():
    docs = expand_log_sample(_alerts(), _cw())
    lo = date(2026, 9, 22)
    hi = date(2026, 10, 5)
    for d in docs:
        d_date = date.fromisoformat(d["time"][:10])
        assert lo <= d_date <= hi, d


def test_expand_message_matches_event_id():
    docs = expand_log_sample(_alerts(), _cw())
    for d in docs:
        if d["event_id"] == 4624:
            assert "successfully logged on" in d["message"]
        elif d["event_id"] == 4625:
            assert "failed to log on" in d["message"]


def test_expand_outcome_matches_success():
    docs = expand_log_sample(_alerts(), _cw())
    for d in docs:
        assert d["outcome"] == ("success" if d["success"] else "failure")


def test_expand_burst_scenario_and_count():
    docs = expand_log_sample(_alerts(), _cw())
    burst_docs = [d for d in docs if d.get("scenario") == "bruteforce_dc"]
    assert len(burst_docs) == 120
    for d in burst_docs:
        assert d["event_id"] == 4625
        assert d["computer"] == "dc-01"
        assert d["target_user"] == "chi.tran1"
        assert d["synthetic"] is True
        assert d["asset_canonical_id"] is not None
        assert d["user_canonical_id"] is not None


@pytest.mark.integration
def test_index_alerts_real(os_client):
    result = index_alerts(client=os_client)
    assert result["errors"] == 0
    assert result["count"] == 1620
    os_client.indices.refresh(index=ALERTS_INDEX)
    count = os_client.count(index=ALERTS_INDEX)["count"]
    assert count >= 1620
