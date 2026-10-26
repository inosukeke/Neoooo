"""Nhân bản log alert gốc (30 record) thành log lớn hơn + bulk index OpenSearch.

30 alert ở `src/ingestion/normalized/alerts.json` quá ít để full-text/aggregation
có ý nghĩa demo. `expand_log_sample` nhân bản mỗi alert gốc `factor` lần (giữ
event_id/computer/target_user, chỉ dịch thời gian trong `days` ngày gần đây,
jitter ±30 phút, tất định theo `seed`) + thêm `burst` doc 4625 mô phỏng
bruteforce nhằm vào domain controller. `index_alerts` bulk nạp kết quả vào
index `security-alerts` (`os_client.ALERTS_MAPPING`).

Thuần đọc normalized/ + crosswalk, không ghi lại file nguồn.

Bulk retry (S4.5): wrap helpers.bulk trong retry loop với exponential backoff
khi OpenSearch trả 429 (rate limit) hoặc 503 (unavailable). Idempotent nhờ
_id = alert_id (rerun cùng input -> cùng _id -> OpenSearch overwrite, không nhân đôi).
"""

import json
import logging
import os
import random
import time
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

logger = logging.getLogger(__name__)

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

    # 3 scenarios bổ sung (S2 D.3): lateral movement, audit cleared, new privilege
    _add_scenario_alerts(out, cw)

    return out


def _emit_scenario_doc(
    out: list[dict],
    *,
    scenario_name: str,
    event_id: int,
    computer: str,
    target_user: str | None,
    success: bool,
    severity: str,
    rule: str,
    start_time: datetime,
    count: int,
    interval_seconds: int,
    cw: dict,
    extras: dict | None = None,
) -> None:
    """Helper chung cho 3 scenarios bổ sung (S2 D.3) — phát sinh N alert liên tiếp
    cách nhau `interval_seconds` giây, share cùng `scenario_name`."""
    extras = extras or {}
    asset_id = asset_canonical_id(cw, "log", computer) if computer else None
    user_id = user_canonical_id(cw, "idp", target_user) if target_user else None
    for i in range(count):
        t = start_time + timedelta(seconds=interval_seconds * i)
        doc_id = f"AL-{scenario_name}-{i:03d}"
        doc = {
            "event_id": event_id,
            "time": t.strftime(TIME_FMT),
            "computer": computer,
            "target_user": target_user,
            "success": success,
            "source": "log",
            "alert_id": doc_id,
            "orig_alert_id": doc_id,
            "asset_canonical_id": asset_id,
            "user_canonical_id": user_id,
            "severity": severity,
            "rule": rule,
            "outcome": _outcome(success),
            "message": _message(event_id, target_user or "", computer),
            "synthetic": True,
            "scenario": scenario_name,
        }
        doc.update(extras)
        out.append(doc)


def _add_scenario_alerts(out: list[dict], cw: dict) -> None:
    """Thêm 3 scenarios giả lập (S2 D.3) đa dạng pattern SOC tier-1:
    - lateral_movement_smb: 4624 type=3 (network logon) từ workstation tới server khác
    - audit_cleared: 1102 (audit log cleared — defense evasion)
    - new_privilege: 4672 (special privileges assigned — privilege escalation)
    """
    base = datetime.strptime(BURST_START, TIME_FMT).replace(tzinfo=timezone.utc)
    # Lateral movement: workstation ws-it-01 đăng nhập vào dc-01 (server khác) trong 30 phút
    _emit_scenario_doc(
        out,
        scenario_name="lateral_movement_smb",
        event_id=4624,
        computer="dc-01",
        target_user="chi.tran1",
        success=True,
        severity="high",
        rule="Lateral movement: workstation -> DC (type=3 logon)",
        start_time=base + timedelta(hours=3),
        count=20,
        interval_seconds=90,
        cw=cw,
        extras={"source_ip": "10.0.2.31", "dest_ip": "10.0.3.5", "dest_port": 445},
    )
    # Audit log cleared (defense evasion) — admin xóa security log trên dc-01
    _emit_scenario_doc(
        out,
        scenario_name="audit_cleared",
        event_id=1102,
        computer="dc-01",
        target_user="chi.tran1",
        success=True,
        severity="critical",
        rule="Audit log cleared (1102) — possible defense evasion",
        start_time=base + timedelta(hours=5),
        count=3,
        interval_seconds=600,
        cw=cw,
    )
    # Special privileges assigned (privilege escalation) — user nhận quyền admin
    _emit_scenario_doc(
        out,
        scenario_name="new_privilege",
        event_id=4672,
        computer="ws-it-01",
        target_user="an.nguyen0",
        success=True,
        severity="high",
        rule="Special privileges assigned to new logon (4672)",
        start_time=base + timedelta(hours=7),
        count=10,
        interval_seconds=300,
        cw=cw,
        extras={"process_name": "powershell.exe", "parent_process": "explorer.exe"},
    )


def _bulk_with_retry(client, *, max_retries: int = 3, **bulk_kwargs):
    """helpers.bulk wrapper với exponential backoff khi lỗi 429/503.

    OpenSearch trả list `errors` cho mỗi doc fail. Nếu bất kỳ error nào có
    status 429/503 -> sleep backoff rồi retry toàn bộ batch (idempotent nhờ
    `_id` ổn định). max_retries=3 mặc định (4 tổng lần thử), backoff 1s/2s/4s.
    Trả tuple (success_count, errors_list) như helpers.bulk."""
    delay = 1.0
    for attempt in range(max_retries + 1):
        success, errors = helpers.bulk(client, **bulk_kwargs, raise_on_error=False)
        # Lọc error transient (429/503) — những lỗi khác (vd mapping conflict)
        # raise ngay, không retry.
        retryable = [
            e for e in (errors if isinstance(errors, list) else [])
            if isinstance(e, dict) and e.get("status") in (429, 503)
        ]
        if not retryable or attempt == max_retries:
            return success, errors
        logger.warning(
            "bulk index gặp %d lỗi transient, sleep %.1fs rồi retry (lần %d/%d)",
            len(retryable), delay, attempt + 1, max_retries,
        )
        time.sleep(delay)
        delay *= 2
    return success, errors  # unreachable, nhưng để mypy yên tâm


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
    success, errors = _bulk_with_retry(client, actions=actions)
    client.indices.refresh(index=ALERTS_INDEX)

    err_count = len(errors) if isinstance(errors, list) else errors
    print(f"Indexed {success} alert docs vao '{ALERTS_INDEX}' ({err_count} loi)")
    return {"count": success, "errors": err_count}


if __name__ == "__main__":
    index_alerts()
