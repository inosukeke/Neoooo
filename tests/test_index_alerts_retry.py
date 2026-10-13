"""Unit test cho src/search/index_alerts.py — _bulk_with_retry() (S4.5).
Mock OpenSearch client để verify retry/backoff logic không cần OpenSearch thật."""

from unittest.mock import MagicMock, patch

import index_alerts


def _mock_bulk_with_errors(errors_per_call):
    """Trả helper fake gọi tuần tự các error sets khác nhau mỗi lần bulk."""
    calls = {"n": 0}

    def fake_bulk(client, **kwargs):
        idx = min(calls["n"], len(errors_per_call) - 1)
        calls["n"] += 1
        return 100, errors_per_call[idx]

    return fake_bulk, calls


def test_bulk_retry_no_errors_returns_immediately():
    """Không có error -> không retry, không sleep."""
    fake_bulk, calls = _mock_bulk_with_errors([[]])

    client = MagicMock()
    with (
        patch.object(index_alerts.helpers, "bulk", side_effect=fake_bulk),
        patch.object(index_alerts.time, "sleep") as mock_sleep,
    ):
        _success, errors = index_alerts._bulk_with_retry(
            client, actions=[{"_id": "x", "_source": {}}]
        )

    assert calls["n"] == 1
    assert errors == []
    mock_sleep.assert_not_called()


def test_bulk_retry_429_succeeds_after_retry():
    """Lần 1 trả 5 error 429, lần 2 (sau sleep) trả rỗng -> return success=100, errors=[]."""
    fake_bulk, calls = _mock_bulk_with_errors([
        [{"status": 429, "error": "rate limit"}] * 5,
        [],
    ])

    client = MagicMock()
    sleep_calls = []
    with (
        patch.object(index_alerts.helpers, "bulk", side_effect=fake_bulk),
        patch.object(
            index_alerts.time, "sleep", side_effect=lambda s: sleep_calls.append(s)
        ),
    ):
        success, errors = index_alerts._bulk_with_retry(
            client, actions=[{"_id": "x", "_source": {}}]
        )

    assert calls["n"] == 2
    assert success == 100
    assert errors == []
    assert sleep_calls == [1.0]


def test_bulk_retry_exponential_backoff():
    """Retry 3 lần với backoff 1s, 2s, 4s rồi cuối cùng fail -> trả errors cuối."""
    fake_bulk, calls = _mock_bulk_with_errors([
        [{"status": 429}] * 3,
        [{"status": 429}] * 3,
        [{"status": 429}] * 3,
        [{"status": 503}] * 3,
    ])

    client = MagicMock()
    sleep_calls = []
    with (
        patch.object(index_alerts.helpers, "bulk", side_effect=fake_bulk),
        patch.object(
            index_alerts.time, "sleep", side_effect=lambda s: sleep_calls.append(s)
        ),
    ):
        success, errors = index_alerts._bulk_with_retry(
            client, actions=[{"_id": "x", "_source": {}}], max_retries=3
        )

    assert calls["n"] == 4
    assert success == 100
    assert sleep_calls == [1.0, 2.0, 4.0]
    assert all(e.get("status") == 503 for e in errors)


def test_bulk_retry_non_retryable_error_no_retry():
    """Lỗi 400 (mapping conflict) -> không retry, return ngay."""
    fake_bulk, calls = _mock_bulk_with_errors([
        [{"status": 400, "error": "mapper_parsing_exception"}],
    ])

    client = MagicMock()
    with (
        patch.object(index_alerts.helpers, "bulk", side_effect=fake_bulk),
        patch.object(index_alerts.time, "sleep") as mock_sleep,
    ):
        success, errors = index_alerts._bulk_with_retry(
            client, actions=[{"_id": "x", "_source": {}}]
        )

    assert calls["n"] == 1
    assert success == 100
    assert errors[0]["status"] == 400
    mock_sleep.assert_not_called()


def test_bulk_retry_mixed_errors_still_retries():
    """Lỗi 429 lẫn lỗi 400 -> vẫn retry vì có retryable."""
    fake_bulk, calls = _mock_bulk_with_errors([
        [{"status": 429}, {"status": 400}],
        [],
    ])

    client = MagicMock()
    sleep_calls = []
    with (
        patch.object(index_alerts.helpers, "bulk", side_effect=fake_bulk),
        patch.object(
            index_alerts.time, "sleep", side_effect=lambda s: sleep_calls.append(s)
        ),
    ):
        _success, errors = index_alerts._bulk_with_retry(
            client, actions=[{"_id": "x", "_source": {}}]
        )

    assert calls["n"] == 2
    assert sleep_calls == [1.0]
    assert errors == []