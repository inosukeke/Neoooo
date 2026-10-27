"""Bảng rule suy diễn ADMIN_TO, CONNECTS_TO, CVE→Service — load từ rules.yaml
(commit S1.2). GIẢ ĐỊNH NGHIỆP VỤ DEMO, KHÔNG PHẢI DỮ LIỆU ĐO THẬT.

Mọi rule ở `src/graph/rules.yaml` đều có metadata `source` / `last_reviewed`
để giám khảo/reviewer truy vết nguồn gốc khi hỏi "rule R1 từ đâu". Xem comment
đầu file YAML để biết thêm.

Backward compat: các biến `ROLE_BY_PREFIX`, `ZONE_BY_CIDR`, `CVE_SERVICE_RULES`,
`ADMIN_RULES`, `CONNECT_RULES` vẫn được export như cũ — code cũ (load_graph.py,
test_graph_rules.py) không phải đổi.

Thuần xử lý, không đọc file ở runtime NGOẠI TRỪ load YAML 1 lần khi import.
Input cho `derive_*` là list[dict] AssetRow/ServiceRow do graph_rows.py sinh ra.
"""

import re
from pathlib import Path

import yaml

BASE = Path(__file__).parent
RULES_PATH = BASE / "rules.yaml"


def _load_rules(path: Path = RULES_PATH) -> dict:
    """Load rules.yaml 1 lần khi module import. Trả dict với keys
    `asset_role`, `zones`, `admin_rules`, `cve_service_rules`, `connect_rules`."""
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


_RULES = _load_rules()


# ---------- Role detection (giữ nguyên logic từ prefix) ----------
ROLE_BY_PREFIX: dict[str, str] = dict(_RULES["asset_role"]["by_prefix"])


def asset_role(hostname: str) -> str:
    match = re.match(r"[a-z]+", hostname.lower())
    prefix = match.group(0) if match else ""
    return ROLE_BY_PREFIX.get(prefix, "unknown")


# ---------- Network zone ----------
ZONE_BY_CIDR: dict[str, str] = dict(_RULES["zones"]["by_cidr"])


def network_zone(cidr: str | None) -> str | None:
    if cidr is None:
        return None
    return ZONE_BY_CIDR.get(cidr)


# ---------- CVE -> Service (giữ nguyên shape để code cũ không đổi) ----------
CVE_SERVICE_RULES: list[dict] = _RULES["cve_service_rules"]["rules"]


def map_service_vulns(service_rows: list) -> list[dict]:
    rows = []
    for rule in CVE_SERVICE_RULES:
        for svc in service_rows:
            if svc.get("product") != rule["product"]:
                continue
            if rule["version"] is not None and svc.get("version") != rule["version"]:
                continue
            for cve in rule["cves"]:
                rows.append({"service_id": svc["id"], "cve": cve})
    return rows


# ---------- Admin rules (giữ nguyên shape: group -> list[role]) ----------
_ADMIN_RULES_RAW: dict[str, dict] = _RULES["admin_rules"]["mapping"]
ADMIN_RULES: dict[str, list[str]] = {
    group: cfg["roles"] for group, cfg in _ADMIN_RULES_RAW.items()
}


def derive_admin_to(asset_rows: list) -> list[dict]:
    # LƯU Ý (biết, chưa sửa): khác với derive_connects_to (bỏ qua asset không có ip),
    # ADMIN_TO ở đây áp dụng CẢ asset không có ip/đang in_review — xem
    # test_derive_admin_to_no_ip_asset_still_admin. Đây là bất nhất đã biết (review
    # Fix round 1 nêu), KHÔNG đổi behavior ở đây vì sẽ đổi số ADMIN_TO thật đo được
    # từ 16 xuống 15, kéo theo phải sửa EXPECT_RELS["ADMIN_TO"] ở load_graph.py +
    # test_derive_admin_to_and_connects_to_on_real_data + số liệu trong docs — rủi ro
    # dây chuyền không rẻ để sửa trong round fix nhỏ này. Cần quyết định rõ từ Chinh
    # trước khi đổi (giữ 16 hay chấp nhận 15) rồi sửa đồng bộ cả 3 nơi.
    rows = []
    for group, roles in ADMIN_RULES.items():
        if not roles:
            continue
        for asset in asset_rows:
            role = asset_role(asset["hostname"])
            if role in roles:
                rows.append(
                    {"group": group, "asset_canonical_id": asset["canonical_id"]}
                )
    return rows


# ---------- Connect rules (giữ nguyên shape; metadata `source` bị strip) ----------
_CONNECT_RULES_RAW: list[dict] = _RULES["connect_rules"]["rules"]
CONNECT_RULES: list[dict] = [
    {
        "id": r["id"],
        "src": r["src"],
        "dst": r["dst"],
        "ports": r["ports"],
    }
    for r in _CONNECT_RULES_RAW
]


def _matches_selector(asset: dict, selector: dict) -> bool:
    if "hostname" in selector:
        return asset["hostname"] == selector["hostname"]
    if "role" in selector:
        return asset_role(asset["hostname"]) == selector["role"]
    if "zone" in selector:
        return network_zone(asset.get("cidr")) == selector["zone"]
    return False


def derive_connects_to(asset_rows: list, service_rows: list) -> list[dict]:
    """Sinh cạnh CONNECTS_TO theo CONNECT_RULES.

    Tối ưu O(n²) -> O(n×k) bằng index 2 chiều theo (role, zone): mỗi rule
    selector chỉ duyệt qua tập asset cùng role/zone, không phải all asset.
    Với 26 asset hiện tại không khác biệt (đã test <0.5s), nhưng khi scale
    lên 150+ asset sẽ tiết kiệm đáng kể.

    Lưu ý: chỉ asset có IP mới tham gia — asset không IP (chỉ AD/log source)
    gán vào Network "unknown", không có CONNECTS_TO vào/ra (xem S3.7)."""
    open_ports: dict[str, set[int]] = {}
    for svc in service_rows:
        if svc.get("protocol") != "tcp":
            continue
        open_ports.setdefault(svc["asset_canonical_id"], set()).add(svc["port"])

    # Pre-compute role + zone cho mỗi asset (để khỏi gọi lại asset_role/network_zone
    # cho mỗi rule iteration). Index theo role/zone cho O(1) lookup tập candidate.
    with_ip = [a for a in asset_rows if a.get("ip") is not None]
    by_hostname: dict[str, list[dict]] = {}
    by_role: dict[str, list[dict]] = {}
    by_zone: dict[str, list[dict]] = {}
    for a in with_ip:
        by_hostname.setdefault(a["hostname"], []).append(a)
        role = asset_role(a["hostname"])
        by_role.setdefault(role, []).append(a)
        zone = network_zone(a.get("cidr"))
        if zone is not None:
            by_zone.setdefault(zone, []).append(a)

    def candidates(selector: dict) -> list[dict]:
        if "hostname" in selector:
            return by_hostname.get(selector["hostname"], [])
        if "role" in selector:
            return by_role.get(selector["role"], [])
        if "zone" in selector:
            return by_zone.get(selector["zone"], [])
        return []

    edges: dict[tuple[str, str], dict] = {}
    for rule in CONNECT_RULES:
        src_cands = candidates(rule["src"])
        dst_cands = candidates(rule["dst"])
        for src in src_cands:
            for dst in dst_cands:
                if src["canonical_id"] == dst["canonical_id"]:
                    continue
                dst_ports = open_ports.get(dst["canonical_id"], set())
                if not dst_ports:
                    continue
                matched_ports = dst_ports & set(rule["ports"])
                if not matched_ports:
                    continue
                key = (src["canonical_id"], dst["canonical_id"])
                if key not in edges:
                    edges[key] = {
                        "src": key[0],
                        "dst": key[1],
                        "ports": set(),
                        "rules": set(),
                    }
                edges[key]["ports"] |= matched_ports
                edges[key]["rules"].add(rule["id"])

    return [
        {
            "src": e["src"],
            "dst": e["dst"],
            "ports": sorted(e["ports"]),
            "rules": sorted(e["rules"]),
        }
        for e in edges.values()
    ]


def rules_metadata() -> dict:
    """Trả metadata tổng (version, last_reviewed, source) để CLI in ra khi debug
    — chỉ dành cho `python -c "from graph_rules import rules_metadata; print(rules_metadata())"`."""
    return {
        "version": _RULES.get("version"),
        "last_reviewed": _RULES.get("last_reviewed"),
        "source": _RULES.get("source"),
        "rules_path": str(RULES_PATH),
    }