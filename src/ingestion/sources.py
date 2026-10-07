"""Giai đoạn 02 — Module 1/3: parser 6 nguồn an ninh → normalized/*.json.

Đọc theo schema gốc từng nguồn (schema-on-read), nắn về schema chung (asset/service/
vulnerability/user/account/membership/alert), xuất JSON vào normalized/. CHƯA nạp
Neo4j — loader chạy sau Entity resolution (module 2).

Nguồn:
  Nmap XML        -> asset, service        (file data/sample_nmap.xml)
  NVD CVE API 2.0 -> vulnerability.cvss     (API thật, cache cache/nvd_<cve>.json)
  EPSS API        -> vulnerability.epss     (API thật, cache cache/epss_<cve>.json)
  CISA KEV JSON   -> vulnerability.kev      (API thật, cache cache/kev.json)
  Identity (giả)  -> user, account, membership (sinh tất định seed=42)
  Log mẫu JSONL   -> alert                  (file data/sample_logs.jsonl)

Idempotent: identity theo seed; API đọc cache trước khi gọi mạng (chạy lại không
gọi mạng, ra y hệt). Cache được commit để chạy offline/tái lập (xem README).
Backoff khi 429/503, tự giới hạn tốc độ NVD (>=6s/call khi không có key).

API key NVD (tùy chọn, nhanh hơn): đặt biến môi trường NVD_API_KEY (xem security.md,
không hardcode). Dùng: python src/ingestion/sources.py [--refresh]
"""
import json
import os
import random
import sys
import time
import xml.etree.ElementTree as ET

import requests

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
CACHE_DIR = os.path.join(BASE, "cache")
OUT_DIR = os.path.join(BASE, "normalized")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ~28 CVE nổi tiếng, dễ giải thích trong phỏng vấn (mục 8 bài giảng). Đều có thật trên
# NVD, phần lớn nằm trong KEV — đủ để luồng CVE -> EPSS -> KEV -> asset chạy hết.
CVE_IDS = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2017-0144",   # EternalBlue (SMB)
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2021-26855",  # ProxyLogon (Exchange)
    "CVE-2021-34473",  # ProxyShell (Exchange)
    "CVE-2019-0708",   # BlueKeep (RDP)
    "CVE-2014-0160",   # Heartbleed (OpenSSL)
    "CVE-2014-6271",   # Shellshock (bash)
    "CVE-2022-30190",  # Follina (MSDT)
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2023-34362",  # MOVEit Transfer
    "CVE-2023-23397",  # Outlook EoP
    "CVE-2018-13379",  # Fortinet FortiOS SSL VPN
    "CVE-2019-11510",  # Pulse Secure VPN
    "CVE-2020-1472",   # Zerologon (Netlogon/DC)
    "CVE-2021-21972",  # VMware vCenter
    "CVE-2022-1388",   # F5 BIG-IP
    "CVE-2016-5195",   # Dirty COW (Linux kernel)
    "CVE-2021-4034",   # PwnKit (polkit)
    "CVE-2012-1823",   # PHP-CGI
    "CVE-2017-5638",   # Apache Struts (Equifax)
    "CVE-2018-7600",   # Drupalgeddon2
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2020-0601",   # CurveBall (Windows CryptoAPI)
    "CVE-2021-41773",  # Apache httpd path traversal
    "CVE-2022-0847",   # Dirty Pipe (Linux kernel)
]


# ---------- Cache + HTTP (backoff) --------------------------------------------------
def _cache_file(key):
    return os.path.join(CACHE_DIR, key + ".json")


def _cache_has(key):
    return os.path.exists(_cache_file(key))


def _cache_read(key):
    with open(_cache_file(key), encoding="utf-8") as f:
        return json.load(f)


def _cache_write(key, data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(_cache_file(key), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _get(url, params=None, headers=None, timeout=20, max_retries=3):
    """GET có backoff tăng dần khi 429/503 (self-throttle do caller lo bằng sleep)."""
    delay = 1.0
    for attempt in range(max_retries + 1):
        r = requests.get(url, params=params, headers=headers or {}, timeout=timeout)
        if r.status_code in (429, 503) and attempt < max_retries:
            time.sleep(delay)
            delay *= 2
            continue
        r.raise_for_status()
        return r
    r.raise_for_status()
    return r


# ---------- 4.1 Nmap XML ------------------------------------------------------------
def parse_nmap_xml(path):
    root = ET.parse(path).getroot()
    assets, services = [], []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else ip
        assets.append({"ip": ip, "hostname": hostname})
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "asset_ip": ip,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "name": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
    return assets, services


# ---------- 4.2 NVD CVE API 2.0 -----------------------------------------------------
def fetch_nvd_cve(cve_ids, api_key=None, delay=6.0):
    """Mỗi CVE một file cache (nvd_<cve>). Chỉ gọi mạng + sleep cho CVE chưa cache."""
    headers = {"apiKey": api_key} if api_key else {}
    raw = []
    for cve_id in cve_ids:
        key = f"nvd_{cve_id}"
        if not _cache_has(key):
            r = _get(NVD_URL, params={"cveId": cve_id}, headers=headers)
            _cache_write(key, r.json().get("vulnerabilities", []))
            time.sleep(0.6 if api_key else delay)  # self-throttle: 5 req/30s khi không key
        raw.extend(_cache_read(key))
    return raw


def normalize_nvd(raw_items):
    out = []
    for item in raw_items:
        cve = item["cve"]
        score = severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                d = metrics[key][0]["cvssData"]
                score, severity = d.get("baseScore"), d.get("baseSeverity")
                break
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        out.append({"cve_id": cve["id"], "description": desc[:500],
                    "cvss_score": score, "cvss_severity": severity})
    return out


# ---------- 4.3 EPSS ----------------------------------------------------------------
def fetch_epss(cve_ids, batch_size=100):
    """Gộp batch cho CVE chưa cache; lưu tách từng CVE (epss_<cve>) để fetch gia tăng."""
    missing = [c for c in cve_ids if not _cache_has(f"epss_{c}")]
    for i in range(0, len(missing), batch_size):
        batch = missing[i:i + batch_size]
        r = _get(EPSS_URL, params={"cve": ",".join(batch)})
        found = {d["cve"]: d for d in r.json().get("data", [])}
        for c in batch:
            _cache_write(f"epss_{c}", found.get(c))  # None nếu EPSS chưa có điểm cho CVE đó
    out = []
    for c in cve_ids:
        d = _cache_read(f"epss_{c}")
        if d:
            out.append(d)
    return out


def normalize_epss(raw_items):
    return [{"cve_id": d["cve"], "epss": float(d["epss"]), "percentile": float(d["percentile"])}
            for d in raw_items]


# ---------- 4.4 CISA KEV ------------------------------------------------------------
def fetch_kev():
    if not _cache_has("kev"):
        r = _get(KEV_URL, headers={"User-Agent": "Mozilla/5.0"})  # CISA chặn client mặc định
        _cache_write("kev", r.json().get("vulnerabilities", []))
    return _cache_read("kev")


def normalize_kev(raw_items):
    return [{"cve_id": v["cveID"], "kev_date_added": v["dateAdded"],
             "kev_due_date": v.get("dueDate"),
             "kev_ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
            for v in raw_items]


# ---------- 4.5 Identity (giả lập, idempotent theo seed) ----------------------------
FIRST = ["an", "binh", "chi", "dung", "giang", "hieu", "khanh", "linh", "minh", "phong"]
LAST = ["nguyen", "tran", "le", "pham", "hoang", "vu", "do", "ngo"]
GROUPS = ["Domain Admins", "IT-Support", "DB-Admins", "Web-Dev", "Finance"]


def generate_identity(n_users=16, seed=42):
    rnd = random.Random(seed)
    users, accounts, memberships = [], [], []
    for i in range(n_users):
        first, last = rnd.choice(FIRST), rnd.choice(LAST)
        username = f"{first}.{last}{i}"
        users.append({"username": username, "display_name": f"{first.title()} {last.title()}"})
        accounts.append({"username": username, "account_type": "domain",
                         "enabled": rnd.random() > 0.08})
        for g in rnd.sample(GROUPS, k=rnd.choice([1, 1, 2])):
            memberships.append({"username": username, "group": g})
    return users, accounts, memberships


# ---------- 4.6 Log mẫu -------------------------------------------------------------
def parse_log_sample(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("EventID") not in (4624, 4625):
                continue
            events.append({
                "event_id": rec["EventID"],
                "time": rec.get("TimeCreated") or rec.get("@timestamp"),
                "computer": rec.get("Computer"),
                "target_user": rec.get("TargetUserName"),
                "success": rec["EventID"] == 4624,
            })
    return events


# ---------- Validate schema chung (mục 5, ưu tiên Trung bình) -----------------------
REQUIRED = {
    "assets": ["ip", "hostname"],
    "services": ["asset_ip", "port"],
    "vulnerabilities": ["cve_id"],
    "users": ["username"],
    "accounts": ["username"],
    "memberships": ["username", "group"],
    "alerts": ["event_id", "computer"],
}


def validate(name, rows):
    keys = REQUIRED[name]
    for i, row in enumerate(rows):
        for k in keys:
            if row.get(k) in (None, ""):
                raise ValueError(f"{name}[{i}] thiếu khóa bắt buộc '{k}': {row}")


# ---------- Completeness (mục 6) ----------------------------------------------------
def report_completeness(data, cve_ids):
    print("\n--- Completeness ---")
    svc = data["services"]
    svc_with_product = sum(1 for s in svc if s["product"])
    print(f"service có product: {svc_with_product}/{len(svc)}"
          + (f" ({svc_with_product / len(svc):.0%})" if svc else ""))

    vulns = data["vulnerabilities"]
    n_nvd = sum(1 for v in vulns if v.get("cvss_score") is not None)
    n_epss = sum(1 for v in vulns if v.get("epss") is not None)
    n_kev = sum(1 for v in vulns if v.get("kev_date_added") is not None)
    n_all3 = sum(1 for v in vulns
                 if v.get("cvss_score") is not None and v.get("epss") is not None
                 and v.get("kev_date_added") is not None)
    print(f"CVE yêu cầu: {len(cve_ids)} | lấy được NVD: {n_nvd} | EPSS: {n_epss} | KEV: {n_kev}")
    print(f"CVE đủ cả 3 nguồn (NVD+EPSS+KEV): {n_all3}/{len(vulns)}")

    alerts = data["alerts"]
    a_ok = sum(1 for a in alerts if a["target_user"] and a["computer"])
    print(f"alert có đủ computer+target_user: {a_ok}/{len(alerts)}")


# ---------- main --------------------------------------------------------------------
def build_vulnerabilities(cve_ids, api_key):
    """Gộp 3 nguồn theo cùng khóa cve_id (mục 4.7)."""
    vulns = normalize_nvd(fetch_nvd_cve(cve_ids, api_key=api_key))
    epss = {d["cve_id"]: d for d in normalize_epss(fetch_epss(cve_ids))}
    kev = {d["cve_id"]: d for d in normalize_kev(fetch_kev())}
    for v in vulns:
        v.update({k: val for k, val in epss.get(v["cve_id"], {}).items() if k != "cve_id"})
        v.update({k: val for k, val in kev.get(v["cve_id"], {}).items() if k != "cve_id"})
    return vulns


def main():
    refresh = "--refresh" in sys.argv
    if refresh:
        import shutil
        if os.path.isdir(CACHE_DIR):
            shutil.rmtree(CACHE_DIR)
        print("[--refresh] đã xóa cache, sẽ gọi API thật lại")

    os.makedirs(OUT_DIR, exist_ok=True)

    nmap_path = os.path.join(DATA_DIR, "sample_nmap.xml")
    if not os.path.exists(nmap_path):
        sys.exit(f"Thiếu {nmap_path} — chạy: python src/ingestion/gen_fixtures.py trước")
    assets, services = parse_nmap_xml(nmap_path)

    users, accounts, memberships = generate_identity()

    log_path = os.path.join(DATA_DIR, "sample_logs.jsonl")
    alerts = parse_log_sample(log_path) if os.path.exists(log_path) else []

    api_key = os.environ.get("NVD_API_KEY")
    print(f"NVD API key: {'có' if api_key else 'không (self-throttle 6s/CVE)'}")
    try:
        vulns = build_vulnerabilities(CVE_IDS, api_key)
    except requests.RequestException as e:
        print(f"[cảnh báo] không gọi được API ({e}); xuất vulnerabilities rỗng lần này")
        vulns = []

    data = {"assets": assets, "services": services, "vulnerabilities": vulns,
            "users": users, "accounts": accounts, "memberships": memberships, "alerts": alerts}

    for name, rows in data.items():
        validate(name, rows)
        with open(os.path.join(OUT_DIR, f"{name}.json"), "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"{name}: {len(rows)} record -> normalized/{name}.json")

    report_completeness(data, CVE_IDS)

    # Mốc kiểm chứng (mục 10): CVE-2021-44228 đủ 3 nguồn
    log4shell = next((v for v in vulns if v["cve_id"] == "CVE-2021-44228"), None)
    ok = bool(log4shell and log4shell.get("cvss_score") is not None
              and log4shell.get("epss") is not None and log4shell.get("kev_date_added"))
    print("\n[kiểm] CVE-2021-44228 đủ cvss+epss+kev:", "OK" if ok else f"CHƯA ({log4shell})")


if __name__ == "__main__":
    main()
