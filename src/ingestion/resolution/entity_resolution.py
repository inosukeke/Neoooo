"""Giai đoạn 02 — Module 2/3: Entity resolution (module trọng tâm).

Nhận ra các bản ghi từ nhiều nguồn cho CÙNG một thực thể (một máy / một người) rồi
gộp về một canonical_id. Dữ liệu định danh/Nmap ở Module 1 không có biến thể tên, nên
module này TỰ tạo "view" nguồn thứ 2/3 có biến thể (make_ad_view, make_hr_view) để có
bài toán matching thật — đúng như bài giảng §8.

Pipeline (rule entity-resolution.md): blocking (prefix tên chuẩn hóa) → compare (exact
trước, rồi rapidfuzz: fuzz.ratio cho asset, biến thể + token_sort_ratio cho username)
→ decision theo ngưỡng match/review/no_match → union-find gộp cụm (≥3 nguồn) → crosswalk
giữ mọi id gốc. False merge nguy hiểm hơn false split → ngưỡng nghiêng precision, case
mơ hồ vào review (không tự gộp). Audit trail mọi quyết định.

Đọc: ../normalized/{assets,users,accounts,alerts}.json
Ghi: ../resolved/{crosswalk,review_queue,decisions,eval}.json
Idempotent (view sinh tất định). Dùng: python src/ingestion/resolution/entity_resolution.py
"""
import json
import os
import sys
from collections import defaultdict

from rapidfuzz import fuzz

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.abspath(__file__))
NORM_DIR = os.path.normpath(os.path.join(BASE, "..", "normalized"))
OUT_DIR = os.path.normpath(os.path.join(BASE, "..", "resolved"))

# Ngưỡng vận hành: chọn 95 (không phải 85 ví dụ của bài giảng) vì rule security.md —
# false merge nguy hiểm hơn false split. Eval (3 ngưỡng) xác nhận 95 cho P=1.0 (0 gộp
# sai); mọi cặp 70–94 (gồm bẫy ws-hr-01↔ws-hr-02=87.5) rơi review cho người xác nhận tay.
MATCH_TH = 95
REVIEW_TH = 70


# ---------- Chuẩn hóa + blocking (§4.1) ---------------------------------------------
def normalize_name(h):
    h = (h or "").lower().strip()
    h = h.split("@")[0]  # bỏ đuôi email cho username dạng user@lab.local
    for suf in (".lab.local", ".local"):
        if h.endswith(suf):
            h = h[: -len(suf)]
    return h


def block_key(name_norm):
    return name_norm[:2]


# ---------- Union-find (§5) ---------------------------------------------------------
class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


# ---------- Điểm tương đồng ----------------------------------------------------------
def asset_score(a, b):
    na, nb = normalize_name(a), normalize_name(b)
    return 100.0 if na == nb else float(fuzz.ratio(na, nb))


def username_variants(username):
    base = username.split("@")[0].lower()
    parts = base.replace("_", ".").split(".")
    variants = {base, "".join(parts)}
    if len(parts) >= 2:
        variants.add(f"{parts[-1]}.{parts[0]}")  # đảo họ-tên
    return variants


def user_score(u1, u2):
    v1, v2 = username_variants(u1), username_variants(u2)
    if v1 & v2:
        return 100.0
    return float(max(fuzz.token_sort_ratio(a, b) for a in v1 for b in v2))


# ---------- Sinh view nguồn thứ 2/3 có biến thể (§8) --------------------------------
# AD đặt tên khác Nmap: hoa, có FQDN, rút gọn, đổi tên vừa (review), hoặc không có máy đó.
AD_NAME_OVERRIDE = {
    "web-01": "web-01.lab.local",   # FQDN -> normalize cắt đuôi -> khớp 100
    "web-02": "web-2",              # rút số -> ~match
    "file-01": "fileserver-01",     # đổi tên vừa -> review
    "vcenter-01": "vcenter",        # cắt hậu tố -> review
}
AD_ABSENT = {"spare-01", "ws-hr-01"}          # Nmap có, AD không (no-match + bẫy precision)
AD_ONLY = [{"key": "LEGACY-NAS", "hostname": "legacy-nas"},   # AD có, Nmap không
           {"key": "OLD-DC-99", "hostname": "old-dc-99"}]


def make_ad_view(nmap_assets):
    ad = []
    for a in nmap_assets:
        base = a["hostname"]
        if base in AD_ABSENT:
            continue
        ad.append({"key": base.upper(), "hostname": AD_NAME_OVERRIDE.get(base, base.upper())})
    return ad + [dict(x) for x in AD_ONLY]


# HR/IdP đặt username khác AD: email, bỏ chấm, hoặc người không có trong nguồn kia.
HR_NAME_OVERRIDE = {}  # mặc định dùng dạng email; override theo user ở dưới nếu cần
HR_ABSENT_INDICES = {1, 4}       # vài user Nmap/AD có nhưng HR không (no-match)
HR_ONLY = [{"username": "external.contractor99"}]  # HR có, nguồn kia không


def make_hr_view(users):
    hr = []
    for i, u in enumerate(users):
        if i in HR_ABSENT_INDICES:
            continue
        name = u["username"]
        if i % 3 == 0:
            variant = f"{name}@lab.local"          # email
        elif i % 3 == 1:
            variant = name.replace(".", "")          # bỏ chấm: an.nguyen0 -> annguyen0
        else:
            variant = name                            # giữ nguyên
        hr.append({"username": variant, "orig": name})
    return hr + [dict(x, orig=x["username"]) for x in HR_ONLY]


# ---------- Resolve chung cho nhiều nguồn -------------------------------------------
def scored_pairs(records, score_fn):
    """Best-match (§4.2): mỗi record chỉ lấy candidate điểm cao nhất ở từng nguồn khác,
    trong cùng block — không so mọi-với-mọi (tránh rác từ máy tên gần giống). Cặp dedup
    theo frozenset, giữ điểm cao nhất (A->B và B->A có thể chọn khác nhau)."""
    blocks = defaultdict(list)
    for r in records:
        blocks[block_key(normalize_name(r["name"]))].append(r)
    best = {}  # frozenset(id,id) -> dict cặp
    for group in blocks.values():
        by_src = defaultdict(list)
        for r in group:
            by_src[r["source"]].append(r)
        for r in group:
            for src, cands in by_src.items():
                if src == r["source"]:
                    continue
                top = max(cands, key=lambda c: score_fn(r["name"], c["name"]))
                score = round(score_fn(r["name"], top["name"]), 1)
                key = frozenset((r["id"], top["id"]))
                if key not in best or score > best[key]["score"]:
                    best[key] = {"a": r["id"], "b": top["id"], "a_name": r["name"],
                                 "b_name": top["name"], "score": score}
    return list(best.values())


def decide(pairs, match_th=MATCH_TH, review_th=REVIEW_TH):
    for p in pairs:
        p["decision"] = ("match" if p["score"] >= match_th
                         else "review" if p["score"] >= review_th else "no_match")
    return pairs


def cluster(records, pairs):
    uf = UnionFind()
    for r in records:
        uf.find(r["id"])
    for p in pairs:
        if p["decision"] == "match":
            uf.union(p["a"], p["b"])
    clusters = {}
    for r in records:
        clusters.setdefault(uf.find(r["id"]), []).append(r["id"])
    return clusters


def build_crosswalk(clusters, prefix):
    crosswalk = {}
    for i, (_, ids) in enumerate(sorted(clusters.items(), key=lambda kv: str(kv[0]))):
        canonical = f"{prefix}-{i:03d}"
        for src, raw in ids:
            crosswalk[f"{src}:{raw}"] = canonical
    return crosswalk


# ---------- Đánh giá (§6) -----------------------------------------------------------
def evaluate(predicted_pairs, true_pairs):
    predicted, truth = set(predicted_pairs), set(true_pairs)
    tp = len(predicted & truth)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "tp": tp, "fp": fp, "fn": fn}


def pairkey(a, b):
    return frozenset((f"{a[0]}:{a[1]}", f"{b[0]}:{b[1]}"))


# ---------- Dựng nguồn + ground truth -----------------------------------------------
def build_asset_records(assets, alerts):
    ad = make_ad_view(assets)
    log_computers = sorted({a["computer"] for a in alerts if a.get("computer")})
    records = [{"id": ("nmap", a["ip"]), "name": a["hostname"], "source": "nmap"} for a in assets]
    records += [{"id": ("ad", a["key"]), "name": a["hostname"], "source": "ad"} for a in ad]
    records += [{"id": ("log", c), "name": c, "source": "log"} for c in log_computers]

    # Ground truth: cặp thật sự cùng máy (theo base hostname). AD_ABSENT/AD_ONLY/HR... không có cặp.
    base_ip = {a["hostname"]: a["ip"] for a in assets}
    log_set = set(log_computers)
    truth = set()
    for a in assets:
        base = a["hostname"]
        has_ad = base not in AD_ABSENT
        has_log = base in log_set
        if has_ad:
            truth.add(pairkey(("nmap", a["ip"]), ("ad", base.upper())))
        if has_log:
            truth.add(pairkey(("nmap", a["ip"]), ("log", base)))
        if has_ad and has_log:
            truth.add(pairkey(("ad", base.upper()), ("log", base)))
    return records, truth


def build_user_records(users):
    hr = make_hr_view(users)
    records = [{"id": ("idp", u["username"]), "name": u["username"], "source": "idp"} for u in users]
    records += [{"id": ("hr", h["username"]), "name": h["username"], "source": "hr"} for h in hr]
    truth = set()
    for h in hr:
        if h["orig"] in {u["username"] for u in users}:
            truth.add(pairkey(("idp", h["orig"]), ("hr", h["username"])))
    return records, truth


# ---------- main --------------------------------------------------------------------
def load(name):
    with open(os.path.join(NORM_DIR, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def summarize(tag, pairs):
    c = {"match": 0, "review": 0, "no_match": 0}
    for p in pairs:
        c[p["decision"]] += 1
    print(f"{tag}: match={c['match']} review={c['review']} no_match={c['no_match']} (tổng cặp {len(pairs)})")
    return c


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    assets, alerts, users = load("assets"), load("alerts"), load("users")

    # --- Asset ---
    a_records, a_truth = build_asset_records(assets, alerts)
    a_pairs = decide(scored_pairs(a_records, asset_score))
    summarize("ASSET", a_pairs)
    a_clusters = cluster(a_records, a_pairs)
    a_cross = build_crosswalk(a_clusters, "asset")

    # --- User ---
    u_records, u_truth = build_user_records(users)
    u_pairs = decide(scored_pairs(u_records, user_score))
    summarize("USER ", u_pairs)
    u_clusters = cluster(u_records, u_pairs)
    u_cross = build_crosswalk(u_clusters, "user")

    # --- Eval ở 3 ngưỡng (§6.2) ---
    eval_out = {"asset": {}, "user": {}}
    for th in (70, 85, 95):
        a_pred = [pairkey(p["a"], p["b"]) for p in a_pairs if p["score"] >= th]
        u_pred = [pairkey(p["a"], p["b"]) for p in u_pairs if p["score"] >= th]
        eval_out["asset"][th] = evaluate(a_pred, a_truth)
        eval_out["user"][th] = evaluate(u_pred, u_truth)
    print("\n--- Eval precision/recall/F1 (asset) ---")
    for th in (70, 85, 95):
        e = eval_out["asset"][th]
        print(f"  ngưỡng {th}: P={e['precision']} R={e['recall']} F1={e['f1']} (tp={e['tp']} fp={e['fp']} fn={e['fn']})")
    print("--- Eval precision/recall/F1 (user) ---")
    for th in (70, 85, 95):
        e = eval_out["user"][th]
        print(f"  ngưỡng {th}: P={e['precision']} R={e['recall']} F1={e['f1']} (tp={e['tp']} fp={e['fp']} fn={e['fn']})")

    # --- Ghi output ---
    crosswalk = {**a_cross, **u_cross}
    review_queue = ([dict(p, kind="asset") for p in a_pairs if p["decision"] == "review"]
                    + [dict(p, kind="user") for p in u_pairs if p["decision"] == "review"])
    decisions = ([dict(p, kind="asset") for p in a_pairs]
                 + [dict(p, kind="user") for p in u_pairs])
    # id tuple -> chuỗi cho JSON
    for d in review_queue + decisions:
        d["a"], d["b"] = f"{d['a'][0]}:{d['a'][1]}", f"{d['b'][0]}:{d['b'][1]}"

    for fname, obj in [("crosswalk", crosswalk), ("review_queue", review_queue),
                       ("decisions", decisions), ("eval", eval_out)]:
        with open(os.path.join(OUT_DIR, f"{fname}.json"), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    n_canon_a = len(set(a_cross.values()))
    n_canon_u = len(set(u_cross.values()))
    print(f"\ncrosswalk: {len(a_cross)} id asset -> {n_canon_a} canonical | "
          f"{len(u_cross)} id user -> {n_canon_u} canonical")
    print(f"review_queue: {len(review_queue)} cặp | decisions (audit): {len(decisions)} cặp")
    print(f"-> {OUT_DIR}")


if __name__ == "__main__":
    main()
