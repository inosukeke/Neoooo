"""Giai đoạn 02 — Module 1: sinh dữ liệu mẫu tất định cho parser đọc.

Nmap và log là "file tĩnh" trong kiến trúc (mục 2.3/4.1/4.6 bài giảng) — parser đọc
từ file chứ không tự sinh. File này tạo ra hai file đó một cách tất định (cùng seed
→ cùng dữ liệu) để demo chạy lại được mà không cần dựng lab Docker + quét Nmap thật:

  data/sample_nmap.xml    ~20 host up (+ host down / port đóng để test lọc)
  data/sample_logs.jsonl  ~30 sự kiện logon 4624/4625, tham chiếu host Nmap + user thật

Log tham chiếu đúng hostname trong sample_nmap.xml và username do
``sources.generate_identity(seed=42)`` sinh ra, để tầng sau nối được cạnh
AUTHENTICATED_TO (user -> asset). Chạy lại idempotent.

Dùng: python src/ingestion/gen_fixtures.py
"""
import json
import os
import random
import sys
import xml.etree.ElementTree as ET

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

from secgraph.ingestion.sources import generate_identity

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")

# Mạng lab giả lập: DMZ 10.0.1/24, workstation 10.0.2/24, server nội bộ 10.0.3/24.
# product/version chọn loại nổi tiếng để sau này map được với CVE seed (sources.CVE_IDS).
HOSTS = [
    # --- DMZ ---
    {"hostname": "web-01", "ip": "10.0.1.10", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "nginx", "version": "1.18.0"},
        {"id": 80, "proto": "tcp", "open": True, "name": "http", "product": "nginx", "version": "1.18.0"},
        {"id": 22, "proto": "tcp", "open": False, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"}]},
    {"hostname": "web-02", "ip": "10.0.1.11", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "Apache httpd", "version": "2.4.49"},
        {"id": 80, "proto": "tcp", "open": True, "name": "http", "product": "Apache httpd", "version": "2.4.49"}]},
    {"hostname": "vpn-01", "ip": "10.0.1.5", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "Fortinet FortiOS", "version": "6.0.4"},
        {"id": 500, "proto": "udp", "open": True, "name": "isakmp", "product": None, "version": None}]},
    {"hostname": "mail-01", "ip": "10.0.1.20", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "Microsoft Exchange", "version": "15.1"},
        {"id": 25, "proto": "tcp", "open": True, "name": "smtp", "product": "Microsoft Exchange", "version": "15.1"}]},
    {"hostname": "proxy-01", "ip": "10.0.1.30", "up": True, "ports": [
        {"id": 8080, "proto": "tcp", "open": True, "name": "http-proxy", "product": "Squid", "version": "4.10"}]},

    # --- Workstation ---
    {"hostname": "ws-hr-01", "ip": "10.0.2.15", "up": True, "ports": [
        {"id": 3389, "proto": "tcp", "open": True, "name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": None},
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None}]},
    {"hostname": "ws-hr-02", "ip": "10.0.2.16", "up": True, "ports": [
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None}]},
    {"hostname": "ws-fin-01", "ip": "10.0.2.21", "up": True, "ports": [
        {"id": 3389, "proto": "tcp", "open": True, "name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": None},
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None}]},
    {"hostname": "ws-it-01", "ip": "10.0.2.31", "up": True, "ports": [
        {"id": 22, "proto": "tcp", "open": True, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"},
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None}]},
    {"hostname": "ws-dev-01", "ip": "10.0.2.41", "up": True, "ports": [
        {"id": 22, "proto": "tcp", "open": True, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"},
        {"id": 3000, "proto": "tcp", "open": True, "name": "http", "product": "Node.js Express", "version": None}]},

    # --- Server nội bộ ---
    {"hostname": "app-01", "ip": "10.0.3.20", "up": True, "ports": [
        {"id": 8080, "proto": "tcp", "open": True, "name": "http-proxy", "product": "Apache Tomcat", "version": "9.0.50"}]},
    {"hostname": "app-02", "ip": "10.0.3.21", "up": True, "ports": [
        {"id": 8080, "proto": "tcp", "open": True, "name": "http-proxy", "product": "Apache Tomcat", "version": "8.5.0"},
        {"id": 8009, "proto": "tcp", "open": False, "name": "ajp13", "product": None, "version": None}]},
    {"hostname": "db-01", "ip": "10.0.3.30", "up": True, "ports": [
        {"id": 5432, "proto": "tcp", "open": True, "name": "postgresql", "product": "PostgreSQL DB", "version": "13.4"}]},
    {"hostname": "db-02", "ip": "10.0.3.31", "up": True, "ports": [
        {"id": 3306, "proto": "tcp", "open": True, "name": "mysql", "product": "MySQL", "version": "5.7.30"}]},
    {"hostname": "dc-01", "ip": "10.0.3.5", "up": True, "ports": [
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": "SMBv1"},
        {"id": 389, "proto": "tcp", "open": True, "name": "ldap", "product": "Microsoft AD LDAP", "version": None},
        {"id": 88, "proto": "tcp", "open": True, "name": "kerberos-sec", "product": "Microsoft Kerberos", "version": None}]},
    {"hostname": "dc-02", "ip": "10.0.3.6", "up": True, "ports": [
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None},
        {"id": 389, "proto": "tcp", "open": True, "name": "ldap", "product": "Microsoft AD LDAP", "version": None}]},
    {"hostname": "file-01", "ip": "10.0.3.40", "up": True, "ports": [
        {"id": 445, "proto": "tcp", "open": True, "name": "microsoft-ds", "product": "Windows SMB", "version": None},
        {"id": 2049, "proto": "tcp", "open": True, "name": "nfs", "product": None, "version": None}]},
    {"hostname": "vcenter-01", "ip": "10.0.3.50", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "VMware vCenter", "version": "6.7"}]},
    {"hostname": "jenkins-01", "ip": "10.0.3.60", "up": True, "ports": [
        {"id": 8080, "proto": "tcp", "open": True, "name": "http", "product": "Jenkins", "version": "2.263"}]},
    {"hostname": "git-01", "ip": "10.0.3.61", "up": True, "ports": [
        {"id": 443, "proto": "tcp", "open": True, "name": "https", "product": "GitLab", "version": "13.10"},
        {"id": 22, "proto": "tcp", "open": True, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"}]},

    # --- Host down / chỉ có port đóng (để test parser lọc đúng) ---
    {"hostname": "old-print-01", "ip": "10.0.3.99", "up": False, "ports": []},
    {"hostname": "spare-01", "ip": "10.0.3.98", "up": True, "ports": [
        {"id": 23, "proto": "tcp", "open": False, "name": "telnet", "product": None, "version": None}]},
]


def build_nmap_xml():
    run = ET.Element("nmaprun", scanner="nmap", args="nmap -sV -oX scan.xml 10.0.0.0/16")
    for h in HOSTS:
        host = ET.SubElement(run, "host")
        ET.SubElement(host, "status", state="up" if h["up"] else "down", reason="echo-reply")
        ET.SubElement(host, "address", addr=h["ip"], addrtype="ipv4")
        hns = ET.SubElement(host, "hostnames")
        ET.SubElement(hns, "hostname", name=h["hostname"], type="PTR")
        ports = ET.SubElement(host, "ports")
        for p in h["ports"]:
            port = ET.SubElement(ports, "port", protocol=p["proto"], portid=str(p["id"]))
            ET.SubElement(port, "state", state="open" if p["open"] else "closed", reason="syn-ack")
            svc_attr = {"name": p["name"] or "unknown"}
            if p.get("product"):
                svc_attr["product"] = p["product"]
            if p.get("version"):
                svc_attr["version"] = p["version"]
            ET.SubElement(port, "service", **svc_attr)
    ET.indent(run, space="  ")
    return ET.tostring(run, encoding="unicode", xml_declaration=True)


def build_logs(seed=42, n_events=30):
    """Sự kiện logon tham chiếu host Nmap + user thật (để nối AUTHENTICATED_TO sau)."""
    users, _, _ = generate_identity(seed=seed)
    usernames = [u["username"] for u in users]
    # Chỉ logon vào host có thể đăng nhập (workstation + server), không phải thiết bị mạng.
    login_hosts = [h["hostname"] for h in HOSTS
                   if h["up"] and h["hostname"].startswith(("ws-", "db-", "dc-", "app-", "file-", "git-"))]
    rnd = random.Random(seed)
    events = []
    base_h = 8
    for i in range(n_events):
        success = rnd.random() > 0.25  # ~25% logon thất bại
        hh = (base_h + i // 4) % 24
        mm = rnd.randint(0, 59)
        events.append({
            "EventID": 4624 if success else 4625,
            "TimeCreated": f"2026-10-05T{hh:02d}:{mm:02d}:00Z",
            "Computer": rnd.choice(login_hosts),
            "TargetUserName": rnd.choice(usernames),
            "LogonType": rnd.choice([2, 3, 10]),
        })
    return events


# --- Nguồn AD (góc nhìn khác của cùng máy, tên biến thể) ------------------------------
# AD đặt tên khác Nmap: hoa, FQDN, rút gọn, đổi tên vừa (review), hoặc không có máy đó.
AD_NAME_OVERRIDE = {
    "web-01": "web-01.lab.local",   # FQDN -> normalize cắt đuôi -> khớp 100
    "web-02": "web-2",              # rút số -> ~match
    "file-01": "fileserver-01",     # đổi tên vừa -> review
    "vcenter-01": "vcenter",        # cắt hậu tố -> review
}
AD_ABSENT = {"spare-01", "ws-hr-01"}          # Nmap có, AD không (no-match + bẫy precision)
AD_ONLY = [{"ad_key": "LEGACY-NAS", "hostname": "legacy-nas"},   # AD có, Nmap không
           {"ad_key": "OLD-DC-99", "hostname": "old-dc-99"}]


def build_ad_view():
    ad = []
    for h in HOSTS:
        if not h["up"] or h["hostname"] in AD_ABSENT:
            continue
        base = h["hostname"]
        ad.append({"ad_key": base.upper(), "hostname": AD_NAME_OVERRIDE.get(base, base.upper())})
    return ad + [dict(x) for x in AD_ONLY]


# --- Nguồn HR (góc nhìn khác của cùng user, tên biến thể) -----------------------------
HR_ABSENT_INDICES = {1, 4}                       # user IdP có nhưng HR không (no-match)
HR_ONLY = ["external.contractor99"]              # HR có, IdP không


def build_hr_view(seed=42):
    users, _, _ = generate_identity(seed=seed)
    hr = []
    for i, u in enumerate(users):
        if i in HR_ABSENT_INDICES:
            continue
        name = u["username"]
        if i % 3 == 0:
            variant = f"{name}@lab.local"       # email
        elif i % 3 == 1:
            variant = name.replace(".", "")       # bỏ chấm: an.nguyen0 -> annguyen0
        else:
            variant = name                        # giữ nguyên
        hr.append({"username": variant, "orig": name})  # orig chỉ để dựng truth, không ghi ra
    hr += [{"username": x, "orig": None} for x in HR_ONLY]
    return hr


# --- Ground truth cho eval (biến thể là tổng hợp nên biết chính xác cặp nào cùng thực thể) ---
def build_truth(logs, hr_view):
    log_computers = {e["Computer"] for e in logs}
    asset, user = [], []
    for h in HOSTS:
        if not h["up"]:
            continue
        base, ip = h["hostname"], h["ip"]
        has_ad = base not in AD_ABSENT
        has_log = base in log_computers
        if has_ad:
            asset.append([f"nmap:{ip}", f"ad:{base.upper()}"])
        if has_log:
            asset.append([f"nmap:{ip}", f"log:{base}"])
        if has_ad and has_log:
            asset.append([f"ad:{base.upper()}", f"log:{base}"])
    for h in hr_view:
        if h["orig"]:
            user.append([f"idp:{h['orig']}", f"hr:{h['username']}"])
    return {"asset": asset, "user": user}


def _write(path, obj, lines=False):
    with open(path, "w", encoding="utf-8") as f:
        if lines:
            f.writelines(json.dumps(e, ensure_ascii=False) + "\n" for e in obj)
        else:
            json.dump(obj, f, ensure_ascii=False, indent=2)


def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    nmap_path = os.path.join(DATA_DIR, "sample_nmap.xml")
    with open(nmap_path, "w", encoding="utf-8") as f:
        f.write(build_nmap_xml())
    n_up = sum(1 for h in HOSTS if h["up"])
    n_open = sum(1 for h in HOSTS for p in h["ports"] if p["open"])
    print(f"sample_nmap.xml: {len(HOSTS)} host ({n_up} up), {n_open} port mở")

    logs = build_logs()
    _write(os.path.join(DATA_DIR, "sample_logs.jsonl"), logs, lines=True)
    print(f"sample_logs.jsonl: {len(logs)} sự kiện logon")

    ad = build_ad_view()
    _write(os.path.join(DATA_DIR, "sample_ad.json"), ad)
    print(f"sample_ad.json: {len(ad)} máy (nguồn AD, tên biến thể)")

    hr = build_hr_view()
    _write(os.path.join(DATA_DIR, "sample_hr.json"), [{"username": h["username"]} for h in hr])
    print(f"sample_hr.json: {len(hr)} user (nguồn HR, tên biến thể)")

    truth = build_truth(logs, hr)
    _write(os.path.join(DATA_DIR, "er_truth.json"), truth)
    print(f"er_truth.json: {len(truth['asset'])} cặp asset + {len(truth['user'])} cặp user (nhãn eval)")
    print(f"-> {DATA_DIR}")


if __name__ == "__main__":
    main()
