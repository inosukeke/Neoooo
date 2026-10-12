"""Bảng rule suy diễn ADMIN_TO, CONNECTS_TO, CVE→Service — GIẢ ĐỊNH NGHIỆP VỤ DEMO,
KHÔNG PHẢI DỮ LIỆU ĐO THẬT. Pipeline Giai đoạn 02 không có nguồn dữ liệu thật cho 3
quan hệ này (xem mo-hinh-hoa-du-lieu.md § "Nạp từ pipeline Giai đoạn 02").

Thuần xử lý, không đọc file / không kết nối Neo4j. Input là list[dict] AssetRow/ServiceRow
do graph_rows.py sinh ra (import nhau là cố ý KHÔNG có ở đây — xem brief T007/T008).
"""

import re

ROLE_BY_PREFIX = {
    "web": "web",
    "vpn": "vpn",
    "mail": "mail",
    "proxy": "proxy",
    "ws": "workstation",
    "app": "app",
    "db": "db",
    "dc": "dc",
    "file": "file",
    "fileserver": "file",
    "vcenter": "hypervisor",
    "jenkins": "ci",
    "git": "scm",
}
ZONE_BY_CIDR = {
    "10.0.1.0/24": "dmz",
    "10.0.2.0/24": "workstation",
    "10.0.3.0/24": "server",
}


def asset_role(hostname: str) -> str:
    match = re.match(r"[a-z]+", hostname.lower())
    prefix = match.group(0) if match else ""
    return ROLE_BY_PREFIX.get(prefix, "unknown")


def network_zone(cidr: str | None) -> str | None:
    if cidr is None:
        return None
    return ZONE_BY_CIDR.get(cidr)


CVE_SERVICE_RULES = [
    {"product": "Apache httpd", "version": "2.4.49", "cves": ["CVE-2021-41773"]},
    {"product": "Fortinet FortiOS", "version": "6.0.4", "cves": ["CVE-2018-13379"]},
    {
        "product": "Microsoft Exchange",
        "version": "15.1",
        "cves": ["CVE-2021-26855", "CVE-2021-34473"],
    },
    {
        "product": "Apache Tomcat",
        "version": "9.0.50",
        "cves": ["CVE-2021-44228", "CVE-2022-22965"],
    },
    {"product": "Apache Tomcat", "version": "8.5.0", "cves": ["CVE-2017-5638"]},
    {"product": "Windows SMB", "version": "SMBv1", "cves": ["CVE-2017-0144"]},
    # version=None khớp MỌI version của product, KỂ CẢ "không rõ version" (Nmap không
    # detect được) — giả định cố ý cho demo (vd CVE-2019-0708/BlueKeep thực ra chỉ ảnh
    # hưởng Win7/2008 cũ, không phải mọi bản Terminal Services). Không phải bug, chỉ
    # ghi rõ để người đọc sau không hiểu nhầm.
    {
        "product": "Microsoft Terminal Services",
        "version": None,
        "cves": ["CVE-2019-0708"],
    },
    {"product": "Microsoft AD LDAP", "version": None, "cves": ["CVE-2020-1472"]},
    {"product": "VMware vCenter", "version": "6.7", "cves": ["CVE-2021-21972"]},
]


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


ADMIN_RULES = {
    "Domain Admins": ["dc"],
    "IT-Support": ["workstation"],
    "DB-Admins": ["db"],
    "Web-Dev": ["web", "app", "ci", "scm"],
    "Finance": [],
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


CONNECT_RULES = [
    {"id": "R1", "src": {"role": "web"}, "dst": {"role": "app"}, "ports": [8080]},
    {"id": "R2", "src": {"role": "app"}, "dst": {"role": "db"}, "ports": [5432, 3306]},
    {
        "id": "R3",
        "src": {"zone": "workstation"},
        "dst": {"role": "dc"},
        "ports": [88, 389, 445],
    },
    {
        "id": "R4",
        "src": {"zone": "workstation"},
        "dst": {"role": "file"},
        "ports": [445],
    },
    {
        "id": "R5",
        "src": {"role": "vpn"},
        "dst": {"zone": "workstation"},
        "ports": [3389],
    },
    {
        "id": "R6",
        "src": {"hostname": "ws-it-01"},
        "dst": {"zone": "server"},
        "ports": [22, 443, 445, 3306, 3389, 5432, 8080],
    },
    {
        "id": "R7",
        "src": {"hostname": "ws-dev-01"},
        "dst": {"role": "scm"},
        "ports": [22, 443],
    },
    {
        "id": "R7b",
        "src": {"hostname": "ws-dev-01"},
        "dst": {"role": "ci"},
        "ports": [8080],
    },
    {"id": "R8", "src": {"role": "ci"}, "dst": {"role": "app"}, "ports": [8080]},
    {"id": "R9", "src": {"role": "mail"}, "dst": {"role": "dc"}, "ports": [88, 389]},
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
    open_ports: dict[str, set[int]] = {}
    for svc in service_rows:
        if svc.get("protocol") != "tcp":
            continue
        open_ports.setdefault(svc["asset_canonical_id"], set()).add(svc["port"])

    edges: dict[tuple[str, str], dict] = {}
    for src in asset_rows:
        if src.get("ip") is None:
            continue
        for dst in asset_rows:
            if dst.get("ip") is None:
                continue
            if src["canonical_id"] == dst["canonical_id"]:
                continue
            dst_ports = open_ports.get(dst["canonical_id"], set())
            if not dst_ports:
                continue
            for rule in CONNECT_RULES:
                if not _matches_selector(src, rule["src"]):
                    continue
                if not _matches_selector(dst, rule["dst"]):
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
