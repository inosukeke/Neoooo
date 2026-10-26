"""Adapter `deepeval` cho metric GraphRAG (retrieval + generation), tách riêng
khỏi lõi harness. `deepeval` là import OPTIONAL: thiếu thì `HAS_DEEPEVAL=False`
và `graphrag_metrics` trả `{}` kèm cảnh báo — harness không bao giờ sập vì nó.

Tách retrieval (contextual precision/recall/relevancy) và generation (answer
relevancy, faithfulness) để biết sửa ở đâu (xem `.claude/rules/eval.md`).
"""

import json
import warnings

# API 4.x — verify `pip show deepeval` + docstring trước khi tin cú pháp
# class/tham số. Code dưới viết theo API deepeval phổ biến (LLMTestCase +
# metric.measure) và CHƯA chạy thử vì deepeval chưa được cài ở môi trường dev.
try:
    from deepeval.metrics import (
        AnswerRelevancyMetric,
        ContextualPrecisionMetric,
        ContextualRecallMetric,
        ContextualRelevancyMetric,
        FaithfulnessMetric,
    )
    from deepeval.test_case import LLMTestCase

    HAS_DEEPEVAL = True
except Exception:  # noqa: BLE001 - ImportError hoặc lỗi khởi tạo thư viện đều coi là "không có"
    HAS_DEEPEVAL = False


def context_to_list(context: str) -> list[str]:
    """`GraphRAGResult.context` là JSON-lines (mỗi record 1 dòng) -> list[str]."""
    return [line for line in (context or "").splitlines() if line.strip()]


def graphrag_metrics(
    question: str,
    answer: str,
    context: str,
    retrieval_context: list[str] | None = None,
    expected_output: str | None = None,
) -> dict:
    """Chấm 1 câu GraphRAG. Trả `{metric_name: {"score": float, "reason": str}}`.

    Không có deepeval -> `{}` + cảnh báo. `ContextualPrecision/Recall` cần
    `expected_output` (đáp án tham chiếu); thiếu thì bỏ 2 metric đó.
    Lỗi từng metric (thường do thiếu LLM judge/API key) ghi vào `reason`,
    `score=None`, không raise."""
    if not HAS_DEEPEVAL:
        warnings.warn(
            "deepeval chưa cài: bỏ qua retrieval/generation metric GraphRAG",
            stacklevel=2,
        )
        return {}
    if retrieval_context is None:
        retrieval_context = context_to_list(context)
    try:
        case = LLMTestCase(
            input=question,
            actual_output=answer,
            expected_output=expected_output,
            retrieval_context=retrieval_context,
            context=retrieval_context,
        )
    except Exception as exc:  # noqa: BLE001
        warnings.warn(f"deepeval LLMTestCase lỗi (API 4.x lệch?): {exc}", stacklevel=2)
        return {}
    metrics = {
        "contextual_relevancy": ContextualRelevancyMetric,
        "answer_relevancy": AnswerRelevancyMetric,
        "faithfulness": FaithfulnessMetric,
    }
    if expected_output:
        metrics["contextual_precision"] = ContextualPrecisionMetric
        metrics["contextual_recall"] = ContextualRecallMetric
    else:
        warnings.warn(
            "thiếu expected_output: bỏ contextual precision/recall", stacklevel=2
        )
    out: dict = {}
    for name, cls in metrics.items():
        try:
            metric = cls()
            metric.measure(case)
            out[name] = {"score": metric.score, "reason": getattr(metric, "reason", "")}
        except Exception as exc:  # noqa: BLE001
            out[name] = {"score": None, "reason": f"lỗi: {exc}"}
    return out


def dumps(metrics: dict) -> str:
    return json.dumps(metrics, ensure_ascii=False)
