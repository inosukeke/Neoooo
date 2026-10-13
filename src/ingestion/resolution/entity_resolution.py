"""Giai đoạn 02 — Module 2/3: Entity resolution (module trọng tâm).

Thuần XỬ LÝ: đọc dữ liệu đã chuẩn hóa đa-nguồn từ Module 1 (normalized/assets.json,
users.json — mỗi record có field `source`) rồi nhận ra các bản ghi từ nhiều nguồn cho
CÙNG một thực thể (một máy / một người) và gộp về một canonical_id. Module này KHÔNG
sinh dữ liệu — việc tạo các nguồn AD/HR (góc nhìn biến thể của cùng thực thể) nằm ở
gen_fixtures.py (tầng nguồn), ground-truth eval ở data/er_truth.json.

Pipeline (rule entity-resolution.md): blocking (prefix tên chuẩn hóa) → compare (exact
trước, rồi rapidfuzz: fuzz.ratio cho asset, biến thể + token_sort_ratio cho username)
→ decision theo ngưỡng match/review/no_match → union-find gộp cụm (≥3 nguồn) → crosswalk
giữ mọi id gốc. False merge nguy hiểm hơn false split → ngưỡng nghiêng precision, case
mơ hồ vào review (không tự gộp). Audit trail mọi quyết định.

Đọc:  ../normalized/{assets,users}.json  +  ../data/er_truth.json
Ghi:  ../resolved/{crosswalk,review_queue,decisions,eval}.json
Idempotent. Dùng: python src/ingestion/resolution/entity_resolution.py
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
DATA_DIR = os.path.normpath(os.path.join(BASE, "..", "data"))
OUT_DIR = os.path.normpath(os.path.join(BASE, "..", "resolved"))

# Ngưỡng vận hành: chọn 95 (không phải 85 ví dụ của bài giảng) vì rule security.md —
# false merge nguy hiểm hơn false split. Eval (3 ngưỡng) xác nhận 95 cho P=1.0 (0 gộp
# sai); mọi cặp 70–94 (gồm bẫy ws-hr-01↔ws-hr-02=87.5) rơi review cho người xác nhận tay.
MATCH_TH = 95
REVIEW_TH = 70


# ---------- Chuẩn hóa + blocking (§4.1) ---------------------------------------------
def normalize_name(h):
    # Lấy nhãn đầu tiên trước dấu '.' = tên ngắn, bỏ MỌI đuôi domain (FQDN) bất kỳ:
    # 'db-01.lab.local' -> 'db-01', 'db-01.corp.com' -> 'db-01'. Tổng quát hơn liệt kê
    # từng đuôi; an toàn vì hostname của ta dùng gạch nối, không có '.' trong tên ngắn.
    # Bỏ đuôi email trước (user@lab.local) rồi mới cắt theo '.'.
    h = (h or "").lower().strip().split("@")[0]
    return h.split(".")[0]


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


# ---------- Resolve chung cho nhiều nguồn -------------------------------------------
def scored_pairs(records, score_fn):
    """Best-match (§4.2): mỗi record chỉ lấy candidate điểm cao nhất ở từng nguồn khác,
    trong cùng block — không so mọi-với-mọi (tránh rác từ máy tên gần giống). Cặp dedup
    theo frozenset, giữ điểm cao nhất (A->B và B->A có thể chọn khác nhau)."""
    blocks = defaultdict(list)
    for r in records:
        blocks[block_key(normalize_name(r["name"]))].append(r)
    best = {}
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
    """Sinh canonical_id tất định `prefix-NNN` cho mỗi cluster.

    Sort theo `str(kv[0])` (UnionFind root có thể là tuple phụ thuộc
    repr Python) — đảm bảo canonical_id ổn định qua nhiều lần
    chạy + Python version, không phụ thuộc repr/hash của tuple."""
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


# ---------- Đọc dữ liệu --------------------------------------------------------------
def load_norm(name):
    with open(os.path.join(NORM_DIR, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def load_truth():
    with open(os.path.join(DATA_DIR, "er_truth.json"), encoding="utf-8") as f:
        t = json.load(f)
    return ({frozenset(p) for p in t["asset"]}, {frozenset(p) for p in t["user"]})


def records_from(rows, namefield):
    return [{"id": (r["source"], r["source_id"]), "name": r[namefield], "source": r["source"]}
            for r in rows]


# ---------- main --------------------------------------------------------------------
def summarize(tag, pairs):
    c = {"match": 0, "review": 0, "no_match": 0}
    for p in pairs:
        c[p["decision"]] += 1
    print(f"{tag}: match={c['match']} review={c['review']} no_match={c['no_match']} (tổng cặp {len(pairs)})")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    a_records = records_from(load_norm("assets"), "hostname")
    u_records = records_from(load_norm("users"), "username")
    a_truth, u_truth = load_truth()

    a_pairs = decide(scored_pairs(a_records, asset_score))
    summarize("ASSET", a_pairs)
    a_cross = build_crosswalk(cluster(a_records, a_pairs), "asset")

    u_pairs = decide(scored_pairs(u_records, user_score))
    summarize("USER ", u_pairs)
    u_cross = build_crosswalk(cluster(u_records, u_pairs), "user")

    # Eval ở 3 ngưỡng (§6.2) so với ground truth sinh kèm
    eval_out = {"asset": {}, "user": {}}
    for th in (70, 85, 95):
        eval_out["asset"][th] = evaluate([pairkey(p["a"], p["b"]) for p in a_pairs if p["score"] >= th], a_truth)
        eval_out["user"][th] = evaluate([pairkey(p["a"], p["b"]) for p in u_pairs if p["score"] >= th], u_truth)
    for kind in ("asset", "user"):
        print(f"--- Eval P/R/F1 ({kind}) ---")
        for th in (70, 85, 95):
            e = eval_out[kind][th]
            print(f"  ngưỡng {th}: P={e['precision']} R={e['recall']} F1={e['f1']} "
                  f"(tp={e['tp']} fp={e['fp']} fn={e['fn']})")

    crosswalk = {**a_cross, **u_cross}
    review_queue = ([dict(p, kind="asset") for p in a_pairs if p["decision"] == "review"]
                    + [dict(p, kind="user") for p in u_pairs if p["decision"] == "review"])
    decisions = [dict(p, kind="asset") for p in a_pairs] + [dict(p, kind="user") for p in u_pairs]
    for d in review_queue + decisions:  # id tuple -> chuỗi cho JSON
        d["a"], d["b"] = f"{d['a'][0]}:{d['a'][1]}", f"{d['b'][0]}:{d['b'][1]}"

    for fname, obj in [("crosswalk", crosswalk), ("review_queue", review_queue),
                       ("decisions", decisions), ("eval", eval_out)]:
        with open(os.path.join(OUT_DIR, f"{fname}.json"), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"\ncrosswalk: {len(a_cross)} id asset -> {len(set(a_cross.values()))} canonical | "
          f"{len(u_cross)} id user -> {len(set(u_cross.values()))} canonical")
    print(f"review_queue: {len(review_queue)} cặp | decisions (audit): {len(decisions)} cặp -> {OUT_DIR}")


if __name__ == "__main__":
    main()
