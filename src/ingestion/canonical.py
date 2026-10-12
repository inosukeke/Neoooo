"""Helper dùng chung cho module OpenSearch (search/) và loader Neo4j (graph/).

Đọc crosswalk.json (output entity resolution, Module 2) để tra canonical_id cho
asset/user theo key f"{source}:{source_id}". Sinh alert_id tất định (hash) và
phân loại severity/rule theo event_id (EVENT_META) cho alert — alert nguồn gốc
(normalized/alerts.json) KHÔNG có id, nên phải sinh ở đây.

Thuần đọc, không ghi file. Dùng: from canonical import enrich_alert, load_crosswalk
"""

import hashlib
import json
import os

BASE = os.path.dirname(os.path.abspath(__file__))
CROSSWALK_PATH = os.path.normpath(os.path.join(BASE, "resolved", "crosswalk.json"))

# event_id -> (severity, rule). Id lạ không có trong bảng -> event_meta() tự fallback.
EVENT_META = {
    4624: ("info", "Successful logon (4624)"),
    4625: ("low", "Failed logon (4625)"),
}


def load_crosswalk(path: str | None = None) -> dict[str, str]:
    with open(path or CROSSWALK_PATH, encoding="utf-8") as f:
        return json.load(f)


def asset_canonical_id(cw: dict, source: str, source_id: str) -> str | None:
    return cw.get(f"{source}:{source_id}")


def user_canonical_id(cw: dict, source: str, source_id: str) -> str | None:
    return cw.get(f"{source}:{source_id}")


def alert_id(alert: dict) -> str:
    raw = "|".join(
        [
            alert["source"],
            str(alert["event_id"]),
            alert["time"],
            alert["computer"],
            alert["target_user"] or "",
        ]
    )
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    return "AL-" + digest[:12]


def event_meta(event_id: int) -> tuple[str, str]:
    return EVENT_META.get(event_id, ("info", f"Event {event_id}"))


def enrich_alert(alert: dict, cw: dict) -> dict:
    severity, rule = event_meta(alert["event_id"])
    return {
        **alert,
        "alert_id": alert_id(alert),
        "asset_canonical_id": asset_canonical_id(cw, "log", alert["computer"]),
        "user_canonical_id": (
            user_canonical_id(cw, "idp", alert["target_user"])
            if alert.get("target_user")
            else None
        ),
        "severity": severity,
        "rule": rule,
    }
