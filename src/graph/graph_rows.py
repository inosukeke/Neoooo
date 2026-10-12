"""Giai đoạn 02→01 — chuyển normalized/* + resolved/crosswalk.json thành "row" phẳng
sẵn sàng nạp Neo4j (UNWIND $rows MERGE theo canonical_id/khóa tương ứng).

Thuần đọc + biến đổi, KHÔNG kết nối Neo4j (loader thật ở load_graph.py, chưa code).
KHÔNG import graph_rules (cố ý tách — xem contract T007/T008).

Đọc: src/ingestion/normalized/{assets,services,vulnerabilities,users,accounts,
memberships,alerts}.json + src/ingestion/resolved/{crosswalk,review_queue}.json.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
NORM_DIR = os.path.normpath(os.path.join(BASE, "..", "ingestion", "normalized"))
RESOLVED_DIR = os.path.normpath(os.path.join(BASE, "..", "ingestion", "resolved"))

# canonical.py và entity_resolution.py nằm ở src/ingestion[/resolution] — thêm vào
# sys.path để import được khi graph_rows.py không chạy qua pytest.ini pythonpath.
_INGESTION_DIR = os.path.normpath(os.path.join(BASE, "..", "ingestion"))
_RESOLUTION_DIR = os.path.join(_INGESTION_DIR, "resolution")
for _p in (_INGESTION_DIR, _RESOLUTION_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from canonical import asset_canonical_id, enrich_alert, user_canonical_id
from entity_resolution import normalize_name

# Thứ tự ưu tiên nguồn khi gộp field xung đột (xem graph-schema.md).
ASSET_SOURCE_PRIORITY = ("nmap", "log", "ad")
USER_SOURCE_PRIORITY = ("idp", "hr")


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_inputs(norm_dir: str | None = None, resolved_dir: str | None = None) -> dict:
    """Đọc normalized/{assets,services,vulnerabilities,users,accounts,memberships,alerts}.json
    + resolved/{crosswalk,review_queue}.json. Trả dict với đúng các key đó (dữ liệu thô)."""
    norm_dir = norm_dir or NORM_DIR
    resolved_dir = resolved_dir or RESOLVED_DIR
    return {
        "assets": _load_json(os.path.join(norm_dir, "assets.json")),
        "services": _load_json(os.path.join(norm_dir, "services.json")),
        "vulnerabilities": _load_json(os.path.join(norm_dir, "vulnerabilities.json")),
        "users": _load_json(os.path.join(norm_dir, "users.json")),
        "accounts": _load_json(os.path.join(norm_dir, "accounts.json")),
        "memberships": _load_json(os.path.join(norm_dir, "memberships.json")),
        "alerts": _load_json(os.path.join(norm_dir, "alerts.json")),
        "crosswalk": _load_json(os.path.join(resolved_dir, "crosswalk.json")),
        "review_queue": _load_json(os.path.join(resolved_dir, "review_queue.json")),
    }


def _review_ids(review_queue, kind: str, cw: dict) -> set:
    """canonical_id nào (kind 'asset'/'user') xuất hiện ở review_queue.json (field a/b)."""
    ids = set()
    for entry in review_queue:
        if entry.get("kind") != kind:
            continue
        for side in ("a", "b"):
            cid = cw.get(entry[side])
            if cid is not None:
                ids.add(cid)
    return ids


def _cidr_from_ip(ip: str | None) -> str | None:
    """Suy /24 từ ip (xem mo-hinh-hoa-du-lieu.md § Nạp từ pipeline Giai đoạn 02 —
    Network.cidr "suy từ ip"). None nếu asset không có ip (chỉ có bản ghi AD/log)."""
    if ip is None:
        return None
    octets = ip.split(".")
    return f"{'.'.join(octets[:3])}.0/24"


def build_asset_rows(
    assets: list[dict], cw: dict, review_queue: dict | list
) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for rec in assets:
        cid = asset_canonical_id(cw, rec["source"], rec["source_id"])
        if cid is None:
            continue
        groups.setdefault(cid, []).append(rec)

    in_review_ids = _review_ids(review_queue, "asset", cw)

    rows = []
    for cid, recs in groups.items():
        by_source = {r["source"]: r for r in recs}
        hostname = None
        for src in ASSET_SOURCE_PRIORITY:
            if src in by_source:
                raw = by_source[src]["hostname"]
                hostname = normalize_name(raw) if src == "ad" else raw
                break
        ip = by_source["nmap"]["ip"] if "nmap" in by_source else None
        rows.append(
            {
                "canonical_id": cid,
                "hostname": hostname,
                "ip": ip,
                "cidr": _cidr_from_ip(ip),
                "sources": sorted(by_source.keys()),
                "source_ids": sorted(f"{r['source']}:{r['source_id']}" for r in recs),
                "in_review": cid in in_review_ids,
            }
        )
    return rows


def build_service_rows(services: list[dict], cw: dict) -> list[dict]:
    rows = []
    for svc in services:
        asset_cid = asset_canonical_id(cw, "nmap", svc["asset_ip"])
        if asset_cid is None:
            # Không có canonical_id (vd ip không có trong crosswalk) -> bỏ qua, tránh
            # sinh id dạng "None:445/tcp" (xem Fix round 1, minor #5).
            print(
                f"CẢNH BÁO: bỏ qua service {svc.get('asset_ip')}:{svc.get('port')} — không tìm thấy asset_canonical_id"
            )
            continue
        rows.append(
            {
                "id": f"{asset_cid}:{svc['port']}/{svc['protocol']}",
                "asset_canonical_id": asset_cid,
                "port": svc["port"],
                "protocol": svc["protocol"],
                "name": svc["name"],
                "product": svc.get("product"),
                "version": svc.get("version"),
            }
        )
    return rows


def build_vuln_rows(vulns: list[dict]) -> list[dict]:
    rows = []
    for v in vulns:
        rows.append(
            {
                "cve": v["cve_id"],
                "cvss": v["cvss_score"],
                "cvss_severity": v["cvss_severity"],
                "epss": v["epss"],
                "epss_percentile": v["percentile"],
                "kev": v.get("kev_date_added") is not None,
                "kev_date_added": v.get("kev_date_added"),
                "kev_due_date": v.get("kev_due_date"),
                "kev_ransomware": v.get("kev_ransomware"),
                "description": v["description"],
            }
        )
    return rows


def build_user_rows(users: list[dict], cw: dict) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for rec in users:
        cid = user_canonical_id(cw, rec["source"], rec["source_id"])
        if cid is None:
            continue
        groups.setdefault(cid, []).append(rec)

    rows = []
    for cid, recs in groups.items():
        by_source = {r["source"]: r for r in recs}
        username = None
        display_name = None
        for src in USER_SOURCE_PRIORITY:
            if src in by_source:
                raw = by_source[src]["username"]
                username = normalize_name(raw) if src == "hr" else raw
                break
        if "idp" in by_source:
            display_name = by_source["idp"].get("display_name")
        rows.append(
            {
                "canonical_id": cid,
                "username": username,
                "display_name": display_name,
                "sources": sorted(by_source.keys()),
                "source_ids": sorted(f"{r['source']}:{r['source_id']}" for r in recs),
            }
        )
    return rows


def build_account_rows(accounts: list[dict], cw: dict) -> list[dict]:
    rows = []
    for acc in accounts:
        rows.append(
            {
                "name": acc["username"],
                "user_canonical_id": user_canonical_id(
                    cw, acc["source"], acc["username"]
                ),
                "account_type": acc["account_type"],
                "enabled": acc["enabled"],
            }
        )
    return rows


def build_membership_rows(memberships: list[dict]) -> list[dict]:
    return [{"account": m["username"], "group": m["group"]} for m in memberships]


def build_alert_rows(alerts: list[dict], cw: dict) -> list[dict]:
    rows = []
    for alert in alerts:
        e = enrich_alert(alert, cw)
        rows.append(
            {
                "id": e["alert_id"],
                "time": e["time"],
                "event_id": e["event_id"],
                "success": e["success"],
                "severity": e["severity"],
                "rule": e["rule"],
                "asset_canonical_id": e["asset_canonical_id"],
                "account": e.get("target_user"),
            }
        )
    return rows


def build_auth_rows(alerts: list[dict], cw: dict) -> list[dict]:
    """Chỉ từ alert event_id=4624 (logon thành công). last_seen = max(time) theo
    cặp (account, asset_canonical_id)."""
    last_seen: dict[tuple[str, str], str] = {}
    for alert in alerts:
        if alert.get("event_id") != 4624 or not alert.get("success"):
            continue
        account = alert.get("target_user")
        if not account:
            continue
        asset_cid = asset_canonical_id(cw, "log", alert["computer"])
        if asset_cid is None:
            continue
        key = (account, asset_cid)
        time_val = alert["time"]
        if key not in last_seen or time_val > last_seen[key]:
            last_seen[key] = time_val

    return [
        {"account": account, "asset_canonical_id": asset_cid, "last_seen": ts}
        for (account, asset_cid), ts in last_seen.items()
    ]
