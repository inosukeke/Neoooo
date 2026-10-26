"""Test lõi eval harness bằng pipeline giả — không cần LLM/Neo4j/deepeval."""

import json
import warnings
from collections import Counter
from types import SimpleNamespace

import judge
import pytest
from eval_harness import (
    EvalResult,
    compute_cost,
    filter_golden,
    load_golden,
    percentile,
    run_eval,
    summarize,
)

PRICE = {"m": {"prompt": 0.5, "completion": 1.5}}


def t2c(status="ok", rows=None, answer="", errors=None, pt=1000, ct=1000, lat=100):
    return SimpleNamespace(
        status=status,
        rows=rows if rows is not None else [],
        answer=answer,
        errors=errors or [],
        prompt_tokens=pt,
        completion_tokens=ct,
        latency_ms=lat,
        model="m",
    )


def rag(answer="CVE-1 ok", context='{"id": "CVE-1"}', seeds=("CVE-1",), lat=50):
    return SimpleNamespace(
        answer=answer,
        context=context,
        seed_ids=list(seeds),
        prompt_tokens=200,
        completion_tokens=100,
        latency_ms=lat,
        model="m",
    )


def item(cat="structured", pipe="text2cypher", expected=None, **kw):
    return {
        "id": "x",
        "question": "q",
        "category": cat,
        "pipeline": pipe,
        "expected": expected if expected is not None else {"nonempty": True},
        **kw,
    }


def run_one(it, t=None, r=None, **kw):
    out = run_eval(
        [it],
        run_text2cypher=lambda q: t,
        run_graphrag=lambda q: r,
        price_per_1k=PRICE,
        **kw,
    )
    return out[0]


# --- golden.json ---------------------------------------------------------
def test_golden_distribution():
    g = load_golden()
    assert 40 <= len(g) <= 50
    c = Counter(i["category"] for i in g)
    assert c["structured"] == 20
    assert c["fuzzy"] == 15
    assert 5 <= c["adversarial"] <= 10
    assert all(i["pipeline"] in ("text2cypher", "graphrag") for i in g)
    assert all(
        i["pipeline"] == "text2cypher" for i in g if i["category"] == "structured"
    )
    assert all(i["pipeline"] == "graphrag" for i in g if i["category"] == "fuzzy")
    assert all(
        i["attack"] in ("write", "injection")
        for i in g
        if i["category"] == "adversarial"
    )


def test_golden_json_valid_and_unique_ids():
    with open(__import__("eval_harness").GOLDEN_PATH, encoding="utf-8") as f:
        items = json.load(f)
    assert len({i["id"] for i in items}) == len(items)


def test_load_golden_rejects_bad_item(tmp_path):
    p = tmp_path / "g.json"
    p.write_text(
        json.dumps(
            [{"id": "a", "question": "q", "category": "zzz", "pipeline": "graphrag"}]
        )
    )
    with pytest.raises(ValueError):
        load_golden(p)


def test_filter_golden():
    g = load_golden()
    assert all(i["category"] == "fuzzy" for i in filter_golden(g, category="fuzzy"))
    assert len(filter_golden(g, pipeline="graphrag", limit=3)) == 3


# --- execution accuracy --------------------------------------------------
def test_structured_ok_nonempty_passes():
    r = run_one(item(), t=t2c(rows=[{"a": 1}], answer="có"))
    assert r.passed and r.failure_reason is None


def test_structured_contains_keyword():
    it = item(expected={"nonempty": True, "contains": ["dc-01"]})
    assert run_one(it, t=t2c(rows=[{"h": "DC-01"}])).passed
    bad = run_one(it, t=t2c(rows=[{"h": "web"}]))
    assert not bad.passed and bad.failure_reason == "wrong_answer"


def test_structured_empty_result():
    r = run_one(item(), t=t2c(rows=[]))
    assert r.failure_reason == "empty_result"


def test_structured_rejected_is_false_rejection():
    assert (
        run_one(item(), t=t2c(status="rejected_write")).failure_reason
        == "false_rejection"
    )


@pytest.mark.parametrize(
    "err,reason",
    [
        ("Query timed out", "timeout"),
        ("Label không tồn tại trong schema: Foo", "wrong_schema"),
        ("Invalid input 'MATC'", "syntax"),
        ("gì đó khác", "generation_failed"),
        (None, "generation_failed"),
    ],
)
def test_failed_classification(err, reason):
    r = run_one(item(), t=t2c(status="failed", errors=[err] if err else []))
    assert r.failure_reason == reason and not r.passed


def test_pipeline_exception_classified():
    def boom(q):
        raise TimeoutError("slow")

    out = run_eval(
        [item()], run_text2cypher=boom, run_graphrag=boom, price_per_1k=PRICE
    )
    assert out[0].failure_reason == "timeout" and out[0].status == "error"

    def boom2(q):
        raise RuntimeError("x")

    out = run_eval(
        [item()], run_text2cypher=boom2, run_graphrag=boom2, price_per_1k=PRICE
    )
    assert out[0].failure_reason == "pipeline_error"


# --- adversarial ---------------------------------------------------------
def adv(attack, forbid=(), pipe="text2cypher"):
    return item("adversarial", pipe, {"forbid_regex": list(forbid)}, attack=attack)


@pytest.mark.parametrize("status", ["rejected_write", "failed"])
def test_adversarial_write_blocked_passes(status):
    assert run_one(adv("write"), t=t2c(status=status)).passed


def test_adversarial_write_not_blocked_fails():
    r = run_one(adv("write"), t=t2c(status="ok", rows=[{"a": 1}]))
    assert not r.passed and r.failure_reason == "write_not_blocked"


def test_adversarial_node_count_changed_fails():
    counts = iter([158, 100])
    r = run_one(
        adv("write"), t=t2c(status="rejected_write"), node_count=lambda: next(counts)
    )
    assert not r.passed and r.failure_reason == "data_modified"


def test_adversarial_node_count_unchanged_passes():
    r = run_one(adv("write"), t=t2c(status="rejected_write"), node_count=lambda: 158)
    assert r.passed


def test_injection_leak_fails_and_clean_passes():
    a = adv("injection", [r"^\W*PWNED\W*$"], pipe="graphrag")
    leak = run_one(a, r=rag(answer="PWNED"))
    assert not leak.passed and leak.failure_reason == "injection_leak"
    assert run_one(a, r=rag(answer="Không đủ dữ liệu")).passed
    # nhắc lại từ khóa nhưng KHÔNG tuân lệnh thì không phải leak
    assert run_one(a, r=rag(answer="Tôi không thể chỉ trả lời PWNED được")).passed


# --- graphrag ------------------------------------------------------------
def test_graphrag_pass_and_failures():
    it = item("fuzzy", "graphrag", {"contains": ["CVE-1"]})
    assert run_one(it, r=rag()).passed
    assert run_one(it, r=rag(seeds=(), context="")).failure_reason == "no_retrieval"
    # đáp án không có trong seed/context -> lỗi retrieval
    miss = run_one(it, r=rag(answer="không rõ", context='{"id": "x"}', seeds=("x",)))
    assert miss.failure_reason == "retrieval_miss"
    # đáp án có trong seed nhưng answer thiếu -> lỗi generation
    gen = run_one(it, r=rag(answer="không rõ", context='{"id": "CVE-1"}'))
    assert gen.failure_reason == "generation_miss"


def test_graphrag_context_alone_does_not_pass():
    """Context luôn chứa 'CVE-...' nên KHÔNG được dùng để chấm đúng."""
    it = item("fuzzy", "graphrag", {"contains": ["CVE-2017-0144"]})
    r = run_one(it, r=rag(answer="Không rõ", context='{"id": "CVE-2017-0144"}'))
    assert not r.passed


def test_graphrag_abstain():
    it = item("fuzzy", "graphrag", {"abstain": True})
    assert run_one(it, r=rag(answer="Không đủ dữ liệu để trả lời.")).passed
    bad = run_one(it, r=rag(answer="Đó là CVE-2021-44228."))
    assert bad.failure_reason == "hallucinated_answer"


def test_contains_any_and_digit_boundary():
    it = item(expected={"contains_any": ["ldap", "kerberos"]})
    assert run_one(it, t=t2c(rows=[{"s": "LDAP"}])).passed
    assert not run_one(it, t=t2c(rows=[{"s": "ssh"}])).passed
    num = item(expected={"contains": ["26"]})
    assert run_one(num, t=t2c(rows=[{"n": 26}])).passed
    assert not run_one(num, t=t2c(rows=[{"t": "2026-10-05"}])).passed


def test_infra_failure_is_not_a_block():
    r = run_one(
        adv("write"), t=t2c(status="failed", errors=["Connection refused by gateway"])
    )
    assert not r.passed and r.failure_reason == "infra_error"
    # failed do validate/syntax vẫn là chặn thật
    assert run_one(
        adv("write"), t=t2c(status="failed", errors=["Invalid input"])
    ).passed


def test_classify_extra_neo4j_messages():
    r = run_one(item(), t=t2c(status="failed", errors=["Variable `x` not defined"]))
    assert r.failure_reason == "syntax"
    r = run_one(item(), t=t2c(status="failed", errors=["Unknown function 'foo'"]))
    assert r.failure_reason == "syntax"


def test_fingerprint_change_detected_even_if_node_count_same():
    seq = iter([(158, 243, 0, 900), (158, 243, 28, 928)])  # SET v.archived
    r = run_one(
        adv("write"), t=t2c(status="rejected_write"), node_count=lambda: next(seq)
    )
    assert r.failure_reason == "data_modified"


def test_node_count_error_does_not_crash(tmp_path):
    def boom():
        raise RuntimeError("db down")

    log = tmp_path / "l.jsonl"
    r = run_one(
        adv("write"), t=t2c(status="rejected_write"), node_count=boom, log_path=log
    )
    assert r.passed
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert "db down" in rec["node_count_error"][0]


def test_judge_fn_called_for_fuzzy_only_and_logged(tmp_path):
    calls = []

    def fake_judge(q, a, c, rc):
        calls.append((q, rc))
        return {"faithfulness": {"score": 0.5, "reason": ""}}

    fz = item("fuzzy", "graphrag", {"contains": ["CVE-1"]})
    st = item()
    log = tmp_path / "l.jsonl"
    out = run_eval(
        [fz, st],
        run_text2cypher=lambda q: t2c(rows=[{"a": 1}]),
        run_graphrag=lambda q: rag(),
        price_per_1k=PRICE,
        judge_fn=fake_judge,
        log_path=log,
    )
    assert len(calls) == 1 and calls[0][1] == ['{"id": "CVE-1"}']
    assert out[0].judge and out[1].judge is None
    assert summarize(out)["judge_mean"] == {"faithfulness": 0.5}
    assert "judge" in json.loads(log.read_text(encoding="utf-8").splitlines()[0])


def test_golden_questions_not_in_few_shots():
    import difflib
    from pathlib import Path

    fs = json.loads(
        (Path(__file__).parent.parent / "src/llm/text2cypher/few_shots.json").read_text(
            encoding="utf-8"
        )
    )
    shots = [x["question"].casefold().strip() for x in fs]
    for g in load_golden():
        q = g["question"].casefold().strip()
        assert q not in shots, g["id"]
        best = max(difflib.SequenceMatcher(None, q, s).ratio() for s in shots)
        assert best < 0.85, (g["id"], best)


def test_golden_fuzzy_have_specific_targets():
    for g in load_golden():
        if g["category"] != "fuzzy":
            continue
        e = g["expected"]
        kws = e.get("contains", []) + e.get("contains_any", [])
        assert e.get("abstain") or kws, g["id"]
        assert "CVE-" not in kws, g["id"]  # tiền tố trần luôn đúng giả


def test_golden_forbid_regex_compile():
    import re

    for g in load_golden():
        for p in g["expected"].get("forbid_regex", []):
            re.compile(p)
    # sk- không dính "risk-based"
    from eval_harness import _leaked

    e = {"forbid_regex": [r"\bsk-[A-Za-z0-9]{10,}"]}
    assert not _leaked(e, "đây là risk-based approach, disk-usage")
    assert _leaked(e, "key sk-abcdefghij1234")


# --- cost / latency ------------------------------------------------------
def test_cost_from_tokens_and_price():
    # 1000 prompt * 0.5/1k + 1000 completion * 1.5/1k = 2.0
    r = run_one(item(), t=t2c(rows=[{"a": 1}]))
    assert r.cost_usd == pytest.approx(2.0)
    assert (r.prompt_tokens, r.completion_tokens) == (1000, 1000)


def test_compute_cost_variants():
    assert compute_cost(2000, 0, "a", {"a": 0.1}) == pytest.approx(0.2)
    assert compute_cost(1000, 0, "zz", {"default": 0.3}) == pytest.approx(0.3)
    assert compute_cost(1000, 1000, "zz", {}) == 0.0


def test_percentiles():
    data = list(range(1, 101))
    assert percentile(data, 50) == 50
    assert percentile(data, 95) == 95
    assert percentile([], 50) == 0.0
    assert percentile([7], 95) == 7


def test_summarize():
    res = [
        EvalResult(
            "1", "q", "structured", "text2cypher", "ok", True, None, 1.0, 100, 1, 1
        ),
        EvalResult(
            "2", "q", "structured", "text2cypher", "ok", False, "syntax", 3.0, 300, 1, 1
        ),
        EvalResult(
            "3",
            "q",
            "adversarial",
            "text2cypher",
            "rejected_write",
            True,
            None,
            0.0,
            200,
            1,
            1,
        ),
    ]
    s = summarize(res)
    assert s["accuracy_by_category"]["structured"]["accuracy"] == 0.5
    assert s["accuracy_by_category"]["adversarial"]["accuracy"] == 1.0
    assert s["cost_total"] == 4.0
    assert s["cost_per_q"] == pytest.approx(4 / 3)
    assert s["latency_p50"] == 200 and s["latency_p95"] == 300
    assert s["failure_breakdown"] == {"syntax": 1}


def test_each_failure_has_exactly_one_reason():
    res = run_eval(
        [item(), item(), adv("write")],
        run_text2cypher=lambda q: t2c(status="failed"),
        run_graphrag=lambda q: None,
        price_per_1k=PRICE,
    )
    for r in res:
        assert r.passed == (r.failure_reason is None)
        assert r.passed or isinstance(r.failure_reason, str)


def test_full_log_written_before_scoring(tmp_path):
    log = tmp_path / "sub" / "log.jsonl"
    run_one(item(), t=t2c(rows=[{"a": 1}]), log_path=log)
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert rec["result"]["status"] == "ok"


# --- judge ---------------------------------------------------------------
def test_judge_context_to_list():
    assert judge.context_to_list('{"a":1}\n\n{"b":2}\n') == ['{"a":1}', '{"b":2}']


def test_judge_without_deepeval_returns_empty(monkeypatch):
    monkeypatch.setattr(judge, "HAS_DEEPEVAL", False)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert judge.graphrag_metrics("q", "a", "c", ["c"]) == {}
    assert w


def test_judge_with_deepeval_installed():
    pytest.importorskip("deepeval")
    assert judge.HAS_DEEPEVAL


def test_summarize_latency_excludes_errors_and_splits_pipeline():
    res = [
        EvalResult(
            "1", "q", "structured", "text2cypher", "ok", True, None, 0.0, 100, 1, 1
        ),
        EvalResult(
            "2",
            "q",
            "structured",
            "text2cypher",
            "error",
            False,
            "timeout",
            0.0,
            0,
            0,
            0,
        ),
        EvalResult("3", "q", "fuzzy", "graphrag", "ok", True, None, 0.0, 900, 1, 1),
    ]
    s = summarize(res)
    assert s["latency_p50"] == 100 and s["latency_p95"] == 900
    assert s["latency_by_pipeline"]["text2cypher"]["n"] == 1
    assert s["latency_by_pipeline"]["graphrag"]["p95"] == 900


def test_summarize_warns_when_cost_not_configured():
    res = [EvalResult("1", "q", "fuzzy", "graphrag", "ok", True, None, 0.0, 10, 5, 5)]
    w = " ".join(summarize(res)["warnings"])
    assert "CHƯA TÍNH CHI PHÍ" in w and "embedding" in w


def test_main_gates_adversarial(monkeypatch, capsys):
    import eval_harness

    code = eval_harness.main(["--category", "adversarial"])
    assert code == 1
    assert "include-adversarial" in capsys.readouterr().err
