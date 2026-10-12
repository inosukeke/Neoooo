"""Unit test cho src/graph/graph_rules.py — rule suy diễn (giả định demo, không
phải dữ liệu đo thật, xem đầu graph_rules.py). AssetRow/ServiceRow dựng tay, KHÔNG
import graph_rows ở phần unit test (chỉ import ở 2 test tích hợp nhẹ cuối file)."""

from graph_rules import (
    asset_role,
    derive_admin_to,
    derive_connects_to,
    map_service_vulns,
    network_zone,
)


def _asset(canonical_id, hostname, ip=None, cidr=None):
    return {"canonical_id": canonical_id, "hostname": hostname, "ip": ip, "cidr": cidr}


def _service(id_, asset_canonical_id, port, protocol="tcp", product=None, version=None):
    return {
        "id": id_,
        "asset_canonical_id": asset_canonical_id,
        "port": port,
        "protocol": protocol,
        "name": "x",
        "product": product,
        "version": version,
    }


# ---------- asset_role / network_zone ------------------------------------------------
def test_asset_role_known_and_unknown_prefix():
    assert asset_role("fileserver-01") == "file"
    assert asset_role("old-dc-99") == "unknown"


def test_network_zone_known_and_unknown():
    assert network_zone("10.0.2.0/24") == "workstation"
    assert network_zone("10.0.9.0/24") is None
    assert network_zone(None) is None


# ---------- map_service_vulns ---------------------------------------------------------
def test_map_service_vulns_exact_product_version_match():
    services = [
        _service("A:443/tcp", "A", 443, product="Apache httpd", version="2.4.49")
    ]
    rows = map_service_vulns(services)
    assert rows == [{"service_id": "A:443/tcp", "cve": "CVE-2021-41773"}]


def test_map_service_vulns_version_none_matches_any_version():
    services = [
        _service(
            "B:3389/tcp", "B", 3389, product="Microsoft Terminal Services", version=None
        )
    ]
    rows = map_service_vulns(services)
    assert rows == [{"service_id": "B:3389/tcp", "cve": "CVE-2019-0708"}]


def test_map_service_vulns_wrong_version_no_match():
    services = [_service("C:80/tcp", "C", 80, product="Apache httpd", version="2.4.50")]
    assert map_service_vulns(services) == []


def test_map_service_vulns_multi_cve_rule():
    services = [
        _service("D:8080/tcp", "D", 8080, product="Apache Tomcat", version="9.0.50")
    ]
    rows = map_service_vulns(services)
    assert {r["cve"] for r in rows} == {"CVE-2021-44228", "CVE-2022-22965"}


def test_map_service_vulns_no_product_match():
    services = [_service("E:22/tcp", "E", 22, product="OpenSSH", version="8.0")]
    assert map_service_vulns(services) == []


# ---------- derive_admin_to -----------------------------------------------------------
def test_derive_admin_to_matches_role_in_rules():
    assets = [
        _asset("a1", "dc-01"),
        _asset("a2", "ws-hr-01"),
        _asset("a3", "db-01"),
        _asset("a4", "web-01"),
    ]
    rows = derive_admin_to(assets)
    pairs = {(r["group"], r["asset_canonical_id"]) for r in rows}
    assert ("Domain Admins", "a1") in pairs
    assert ("IT-Support", "a2") in pairs
    assert ("DB-Admins", "a3") in pairs
    assert ("Web-Dev", "a4") in pairs


def test_derive_admin_to_no_ip_asset_still_admin():
    # ADMIN_TO áp dụng cả asset không có ip (contract: "áp dụng CẢ asset không có ip").
    assets = [_asset("a5", "dc-02", ip=None)]
    rows = derive_admin_to(assets)
    assert {"group": "Domain Admins", "asset_canonical_id": "a5"} in rows


def test_derive_admin_to_finance_has_no_roles():
    assets = [_asset("a6", "fin-01")]
    rows = derive_admin_to(assets)
    assert all(r["group"] != "Finance" for r in rows)


def test_derive_admin_to_unknown_role_not_admin_anywhere():
    assets = [_asset("a7", "legacy-nas")]
    rows = derive_admin_to(assets)
    assert rows == []


# ---------- derive_connects_to ---------------------------------------------------------
def test_connects_to_r1_web_to_app():
    assets = [
        _asset("web1", "web-01", ip="10.0.1.10"),
        _asset("app1", "app-01", ip="10.0.3.10"),
    ]
    services = [_service("app1:8080/tcp", "app1", 8080)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "web1", "dst": "app1", "ports": [8080], "rules": ["R1"]}]


def test_connects_to_r2_app_to_db():
    assets = [
        _asset("app1", "app-01", ip="10.0.3.10"),
        _asset("db1", "db-01", ip="10.0.3.11"),
    ]
    services = [_service("db1:5432/tcp", "db1", 5432)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "app1", "dst": "db1", "ports": [5432], "rules": ["R2"]}]


def test_connects_to_r3_workstation_zone_to_dc():
    assets = [
        _asset("ws1", "ws-hr-01", ip="10.0.2.15", cidr="10.0.2.0/24"),
        _asset("dc1", "dc-01", ip="10.0.3.12", cidr="10.0.3.0/24"),
    ]
    services = [_service("dc1:389/tcp", "dc1", 389)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "ws1", "dst": "dc1", "ports": [389], "rules": ["R3"]}]


def test_connects_to_r4_workstation_zone_to_file():
    assets = [
        _asset("ws1", "ws-hr-01", ip="10.0.2.15", cidr="10.0.2.0/24"),
        _asset("file1", "file-01", ip="10.0.3.13", cidr="10.0.3.0/24"),
    ]
    services = [_service("file1:445/tcp", "file1", 445)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "ws1", "dst": "file1", "ports": [445], "rules": ["R4"]}]


def test_connects_to_r5_vpn_to_workstation_zone():
    assets = [
        _asset("vpn1", "vpn-01", ip="10.0.1.5", cidr="10.0.1.0/24"),
        _asset("ws1", "ws-hr-01", ip="10.0.2.15", cidr="10.0.2.0/24"),
    ]
    services = [_service("ws1:3389/tcp", "ws1", 3389)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "vpn1", "dst": "ws1", "ports": [3389], "rules": ["R5"]}]


def test_connects_to_r7_ws_dev_to_scm():
    assets = [
        _asset("wsdev", "ws-dev-01", ip="10.0.2.41", cidr="10.0.2.0/24"),
        _asset("git1", "git-01", ip="10.0.3.14", cidr="10.0.3.0/24"),
    ]
    services = [_service("git1:22/tcp", "git1", 22)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "wsdev", "dst": "git1", "ports": [22], "rules": ["R7"]}]


def test_connects_to_r7b_ws_dev_to_ci():
    assets = [
        _asset("wsdev", "ws-dev-01", ip="10.0.2.41", cidr="10.0.2.0/24"),
        _asset("jenkins1", "jenkins-01", ip="10.0.3.15", cidr="10.0.3.0/24"),
    ]
    services = [_service("jenkins1:8080/tcp", "jenkins1", 8080)]
    rows = derive_connects_to(assets, services)
    assert rows == [
        {"src": "wsdev", "dst": "jenkins1", "ports": [8080], "rules": ["R7b"]}
    ]


def test_connects_to_r8_ci_to_app():
    assets = [
        _asset("jenkins1", "jenkins-01", ip="10.0.3.15"),
        _asset("app1", "app-01", ip="10.0.3.10"),
    ]
    services = [_service("app1:8080/tcp", "app1", 8080)]
    rows = derive_connects_to(assets, services)
    assert rows == [
        {"src": "jenkins1", "dst": "app1", "ports": [8080], "rules": ["R8"]}
    ]


def test_connects_to_r9_mail_to_dc():
    assets = [
        _asset("mail1", "mail-01", ip="10.0.1.20"),
        _asset("dc1", "dc-01", ip="10.0.3.12"),
    ]
    services = [_service("dc1:88/tcp", "dc1", 88)]
    rows = derive_connects_to(assets, services)
    assert rows == [{"src": "mail1", "dst": "dc1", "ports": [88], "rules": ["R9"]}]


def test_connects_to_r6_merges_with_r3_on_same_pair():
    """ws-it-01 (R6 theo hostname, dst zone server) và cùng lúc zone 'workstation' (R3,
    dst role dc) khớp CÙNG cặp (src, dst) -> phải hợp nhất thành 1 cạnh, ports là union,
    rules là list đã sort."""
    assets = [
        _asset("wsit", "ws-it-01", ip="10.0.2.31", cidr="10.0.2.0/24"),
        _asset("dc1", "dc-01", ip="10.0.3.12", cidr="10.0.3.0/24"),
    ]
    services = [
        _service("dc1:88/tcp", "dc1", 88),
        _service("dc1:389/tcp", "dc1", 389),
        _service("dc1:445/tcp", "dc1", 445),
    ]
    rows = derive_connects_to(assets, services)
    assert len(rows) == 1
    edge = rows[0]
    assert edge["src"] == "wsit"
    assert edge["dst"] == "dc1"
    assert edge["ports"] == [88, 389, 445]
    assert edge["rules"] == ["R3", "R6"]


def test_connects_to_no_self_loop():
    # 1 asset duy nhất khớp cả src và dst của R6 (hostname + zone server) -> không tự nối.
    assets = [_asset("x1", "ws-it-01", ip="10.0.3.31", cidr="10.0.3.0/24")]
    services = [_service("x1:8080/tcp", "x1", 8080)]
    rows = derive_connects_to(assets, services)
    assert rows == []


def test_connects_to_missing_ip_no_edge():
    assets = [
        _asset("web1", "web-01", ip=None),
        _asset("app1", "app-01", ip="10.0.3.10"),
    ]
    services = [_service("app1:8080/tcp", "app1", 8080)]
    rows = derive_connects_to(assets, services)
    assert rows == []


def test_connects_to_no_open_port_no_edge():
    assets = [
        _asset("web1", "web-01", ip="10.0.1.10"),
        _asset("app1", "app-01", ip="10.0.3.10"),
    ]
    services = [_service("app1:9999/tcp", "app1", 9999)]
    rows = derive_connects_to(assets, services)
    assert rows == []


# ---------- tích hợp nhẹ trên dữ liệu thật (không cần Neo4j) --------------------------
def test_map_service_vulns_on_real_data():
    from graph_rows import build_service_rows, load_inputs

    data = load_inputs()
    services = build_service_rows(data["services"], data["crosswalk"])
    rows = map_service_vulns(services)
    # Số thật đo được: 16 HAS_VULN, 11 CVE phân biệt (brief kỳ vọng 16/11 — khớp).
    assert len(rows) == 16
    assert len({r["cve"] for r in rows}) == 11


def test_derive_admin_to_and_connects_to_on_real_data():
    from graph_rows import build_asset_rows, build_service_rows, load_inputs

    data = load_inputs()
    assets = build_asset_rows(data["assets"], data["crosswalk"], data["review_queue"])
    services = build_service_rows(data["services"], data["crosswalk"])

    admin_rows = derive_admin_to(assets)
    # Số thật đo được: 16 ADMIN_TO (brief kỳ vọng 16 — khớp).
    assert len(admin_rows) == 16

    connect_rows = derive_connects_to(assets, services)
    # Số thật đo được: 38 CONNECTS_TO (brief kỳ vọng 38 — khớp, sau khi graph_rows.py
    # sửa build_asset_rows để suy cidr từ ip, trước đó cidr luôn None -> chỉ ra 14).
    assert len(connect_rows) == 38
