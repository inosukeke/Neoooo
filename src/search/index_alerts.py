"""Nhân bản log alert gốc (30 record) thành log lớn hơn + bulk index OpenSearch.

30 alert ở `src/ingestion/normalized/alerts.json` quá ít để full-text/aggregation
có ý nghĩa demo. `expand_log_sample` nhân bản mỗi alert gốc `factor` lần (giữ
event_id/computer/target_user, chỉ dịch thời gian trong `days` ngày gần đây,
jitter ±30 phút, tất định theo `seed`) + thêm `burst` doc 4625 mô phỏng
bruteforce nhằm vào domain controller. `index_alerts` bulk nạp kết quả vào
index `security-alerts` (`os_client.ALERTS_MAPPING`).

Thuần đọc normalized/ + crosswalk, không ghi lại file nguồn.
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone

from canonical import (
    asset_canonical_id,
    enrich_alert,
    event_meta,
    load_crosswalk,
    user_canonical_id,
)
from opensearchpy import helpers
from os_client import ALERTS_INDEX, ensure_index, make_client

BASE = os.path.dirname(os.path.abspath(__file__))
ALERTS_PATH = os.path.normpath(
    os.path.join(BASE, "..", "ingestion", "normalized", "alerts.json")
)

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Computer/user burst (bruteforce vào domain controller): canonical_id tra qua
# crosswalk key "log:dc-01" chứ không hardcode canonical_id trực tiếp — asset
# có thể có canonical_id khác literal "dc-01" (xem src/ingestion/canonical.py).
BURST_COMPUTER = "dc-01"
BURST_USER = "chi.tran1"  # xác nhận là Domain Admins trong normalized/memberships.json
BURST_START = "2026-10-04T02:00:00Z"


def load_alerts(path: str | None = None) -> list[dict]:
    with open(path or ALERTS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _outcome(success) -> str:
    return "success" if success else "failure"


def _message(event_id: int, target_user: str, computer: str) -> str:
    if event_id == 4624:
        return (
            f"An account was successfully logged on. "
            f"Account Name: {target_user}. Workstation: {computer}."
        )
    if event_id == 4625:
        return (
            f"An account failed to log on. "
            f"Account Name: {target_user}. Workstation: {computer}."
        )
    return f"Event {event_id}. Account Name: {target_user}. Workstation: {computer}."


def expand_log_sample(
    alerts: list[dict],
    cw: dict,
    factor: int = 50,
    days: int = 14,
    seed: int = 42,
    burst: int = 120,
) -> list[dict]:
    """Nhân bản 30 alert gốc thành (factor * len(alerts)) + burst doc, tất định."""
    out: list[dict] = []

    for idx, alert in enumerate(alerts):
        enriched = enrich_alert(alert, cw)
        orig_id = enriched["alert_id"]

        out.append(
            {
                **enriched,
                "synthetic": False,
                "orig_alert_id": orig_id,
                "outcome": _outcome(alert["success"]),
                "message": _message(
                    alert["event_id"], alert["target_user"] or "", alert["computer"]
                ),
            }
        )

        orig_time = datetime.strptime(alert["time"], TIME_FMT).replace(
            tzinfo=timezone.utc
        )
        for k in range(1, factor):
            rng = random.Random(seed + idx * factor + k)
            jitter_seconds = rng.randint(-30 * 60, 30 * 60)
            new_time = (
                orig_time
                - timedelta(days=(k % days))
                + timedelta(seconds=jitter_seconds)
            )
            copy_alert = {**alert, "time": new_time.strftime(TIME_FMT)}
            copy_enriched = enrich_alert(copy_alert, cw)
            out.append(
                {
                    **copy_enriched,
                    "alert_id": f"{orig_id}-x{k:03d}",
                    "orig_alert_id": orig_id,
                    "synthetic": True,
                    "outcome": _outcome(alert["success"]),
                    "message": _message(
                        alert["event_id"], alert["target_user"] or "", alert["computer"]
                    ),
                }
            )

    burst_asset_id = asset_canonical_id(cw, "log", BURST_COMPUTER)
    burst_user_id = user_canonical_id(cw, "idp", BURST_USER)
    severity, rule = event_meta(4625)
    start = datetime.strptime(BURST_START, TIME_FMT).replace(tzinfo=timezone.utc)
    for i in range(burst):
        t = start + timedelta(seconds=30 * i)
        burst_id = f"AL-burst-{i:03d}"
        out.append(
            {
                "event_id": 4625,
                "time": t.strftime(TIME_FMT),
                "computer": BURST_COMPUTER,
                "target_user": BURST_USER,
                "success": False,
                "source": "log",
                "alert_id": burst_id,
                "orig_alert_id": burst_id,
                "asset_canonical_id": burst_asset_id,
                "user_canonical_id": burst_user_id,
                "severity": severity,
                "rule": rule,
                "outcome": "failure",
                "message": _message(4625, BURST_USER, BURST_COMPUTER),
                "synthetic": True,
                "scenario": "bruteforce_dc",
            }
        )

    return out


def index_alerts(client=None) -> dict:
    """Load normalized/alerts.json + crosswalk, expand, bulk index vào OpenSearch."""
    client = client or make_client()
    alerts = load_alerts()
    cw = load_crosswalk()
    docs = expand_log_sample(alerts, cw)

    ensure_index(client)
    actions = (
        {
            "_op_type": "index",
            "_index": ALERTS_INDEX,
            "_id": doc["alert_id"],
            "_source": doc,
        }
        for doc in docs
    )
    success, errors = helpers.bulk(client, actions, raise_on_error=False)
    client.indices.refresh(index=ALERTS_INDEX)

    err_count = len(errors) if isinstance(errors, list) else errors
    print(f"Indexed {success} alert docs vao '{ALERTS_INDEX}' ({err_count} loi)")
    return {"count": success, "errors": err_count}


if __name__ == "__main__":
    index_alerts()
