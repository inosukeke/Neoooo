"""Lắp ráp pipeline 6 bước Text2Cypher (xem `.claude/rules/text2cypher.md`):

sinh schema text -> ghép prompt (temperature=0) -> LLM sinh Cypher -> validate
4 lớp -> thực thi -> LLM diễn giải kết quả. Vòng lặp sửa lỗi quay lại LLM tối
đa `MAX_REPAIRS` lần.

`generate`/`interpret`/`explain`/`execute` là callback tiêm vào từ caller (CLI
ở T018 nối LLM/Neo4j thật; test ở đây dùng hàm giả) — module này không tự gọi
API/DB nào.

Chạy CLI: `python text2cypher.py "<câu hỏi>"` (cần OPENAI_API_KEY,
OPENAI_BASE_URL, TEXT2CYPHER_MODEL, NEO4J_URI trong env). `--check-model` chỉ
kiểm model gateway, không cần Neo4j. `--json` in `Text2CypherResult` dạng JSON
(rows đã qua `to_jsonable` vì có thể chứa kiểu neo4j.time.*)."""

import argparse
import itertools
import json
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from llm_client import ConfigError, chat, check_model, load_llm_config, make_client
from neo4j import GraphDatabase, Query
from prompts import (
    build_generation_messages,
    build_interpret_messages,
    build_repair_messages,
    extract_cypher,
    to_jsonable,
)
from schema_text import GraphSchema, fetch_schema, render_schema_text
from validator import ValidationError, validate_cypher

FEW_SHOTS_PATH = Path(__file__).parent / "few_shots.json"

MAX_REPAIRS = 2
MAX_ROWS = 100
MAX_ROWS_TO_LLM = 50
QUERY_TIMEOUT_SECONDS = 10
EMPTY_ANSWER = "Không tìm thấy dữ liệu phù hợp trong đồ thị."
REJECTED_WRITE_ANSWER = (
    "Câu hỏi yêu cầu hành động không được phép (chỉ hỗ trợ truy vấn đọc dữ liệu)."
)


def _failure_answer(attempts: int, max_attempts: int, errors: list[str]) -> str:
    """Message chi tiết khi pipeline fail sau hết số lần thử — cho user biết
    tại sao thay vì `EMPTY_ANSWER` chung chung. Giữ 1 dòng để CLI/UI hiển thị
    gọn; chi tiết error nằm trong `result.errors`."""
    if not errors:
        return f"Không trả lời được sau {attempts}/{max_attempts} lần thử."
    last = errors[-1]
    # Cắt dòng dài để không tràn terminal, nhưng giữ đủ thông tin.
    if len(last) > 200:
        last = last[:197] + "..."
    return (
        f"Không trả lời được sau {attempts}/{max_attempts} lần thử. "
        f"Lỗi cuối: {last}"
    )


def _finalize_kwargs(
    prompt_tokens: int,
    completion_tokens: int,
    start_ms: int,
    model: str,
) -> dict:
    """Tính latency_ms + trả dict các field usage để spread vào Text2CypherResult."""
    import time as _time

    latency_ms = (_time.monotonic_ns() // 1_000_000) - start_ms
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "latency_ms": latency_ms,
        "model": model,
    }


@dataclass
class Text2CypherResult:
    question: str
    status: Literal["ok", "rejected_write", "failed"]
    cypher: str | None
    attempts: int
    fixes: list[str]
    rows: list[dict]
    answer: str
    errors: list[str] = field(default_factory=list)
    # S5.7: usage stats — đo chi phí + latency (rule eval.md yêu cầu).
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    model: str = ""


def answer_question(
    question: str,
    *,
    schema: GraphSchema,
    few_shots: list[dict],
    generate: Callable[[list[dict]], str],
    interpret: Callable[[list[dict]], str],
    explain: Callable[[str], None],
    execute: Callable[[str], list[dict]],
    model: str = "",
    chat_with_usage: Callable[[list[dict]], tuple[str, dict]] | None = None,
) -> Text2CypherResult:
    """Chạy đủ pipeline 6 bước cho một câu hỏi, trả `Text2CypherResult`.

    Nếu `chat_with_usage` được cung cấp (trả `(text, usage_dict)`), result sẽ
    điền `prompt_tokens`/`completion_tokens` từ `usage_dict`. Nếu không, default
    0 (backward compat với `generate` callback cũ)."""
    import time as _time

    start_ms = _time.monotonic_ns() // 1_000_000
    prompt_tokens_total = 0
    completion_tokens_total = 0
    messages = build_generation_messages(
        question, render_schema_text(schema), few_shots
    )
    errors: list[str] = []

    cypher = ""
    attempts = 0
    fixes: list[str] = []
    max_attempts = 1 + MAX_REPAIRS
    validated = False

    for attempt_num in range(1, max_attempts + 1):
        attempts = attempt_num
        try:
            if chat_with_usage is not None:
                raw, usage = chat_with_usage(messages)
                prompt_tokens_total += usage.get("prompt_tokens", 0)
                completion_tokens_total += usage.get("completion_tokens", 0)
            else:
                raw = generate(messages)
            cypher = extract_cypher(raw)
            result = validate_cypher(cypher, schema, explain)
            fixes = result.fixes
            cypher = result.cypher
            validated = True
            break
        except ValidationError as exc:
            if exc.layer == "readonly":
                return Text2CypherResult(
                    question=question,
                    status="rejected_write",
                    cypher=cypher,
                    attempts=attempts,
                    fixes=[],
                    rows=[],
                    answer=REJECTED_WRITE_ANSWER,
                    errors=errors,
                    **_finalize_kwargs(
                        prompt_tokens_total,
                        completion_tokens_total,
                        start_ms,
                        model,
                    ),
                )
            errors.append(str(exc))
            if attempts < max_attempts:
                messages = build_repair_messages(messages, cypher, str(exc))
        except Exception as exc:  # noqa: BLE001 - lỗi khác từ generate cũng coi là 1 lần thử lỗi
            errors.append(str(exc))
            if attempts < max_attempts:
                messages = build_repair_messages(messages, cypher, str(exc))

    if not validated:
        return Text2CypherResult(
            question=question,
            status="failed",
            cypher=cypher,
            attempts=attempts,
            fixes=[],
            rows=[],
            answer=_failure_answer(attempts, max_attempts, errors),
            errors=errors,
            **_finalize_kwargs(
                prompt_tokens_total,
                completion_tokens_total,
                start_ms,
                model,
            ),
        )

    try:
        rows = execute(cypher)[:MAX_ROWS]
    except Exception as exc:  # noqa: BLE001 - execute lỗi (timeout, DB down...) coi như failed
        errors.append(str(exc))
        return Text2CypherResult(
            question=question,
            status="failed",
            cypher=cypher,
            attempts=attempts,
            fixes=fixes,
            rows=[],
            answer=_failure_answer(attempts, max_attempts, errors),
            errors=errors,
            **_finalize_kwargs(
                prompt_tokens_total,
                completion_tokens_total,
                start_ms,
                model,
            ),
        )

    if not rows:
        return Text2CypherResult(
            question=question,
            status="ok",
            cypher=cypher,
            attempts=attempts,
            fixes=fixes,
            rows=[],
            answer=EMPTY_ANSWER,
            errors=errors,
            **_finalize_kwargs(
                prompt_tokens_total,
                completion_tokens_total,
                start_ms,
                model,
            ),
        )

    rows_for_llm = [to_jsonable(row) for row in rows[:MAX_ROWS_TO_LLM]]
    interpret_messages = build_interpret_messages(question, cypher, rows_for_llm)
    try:
        if chat_with_usage is not None:
            answer, usage = chat_with_usage(interpret_messages)
            prompt_tokens_total += usage.get("prompt_tokens", 0)
            completion_tokens_total += usage.get("completion_tokens", 0)
        else:
            answer = interpret(interpret_messages)
    except Exception as exc:  # noqa: BLE001 - lỗi hạ tầng khi diễn giải (mạng, gateway...) -> failed, không bay ra ngoài
        errors.append(str(exc))
        return Text2CypherResult(
            question=question,
            status="failed",
            cypher=cypher,
            attempts=attempts,
            fixes=fixes,
            rows=rows,
            answer=EMPTY_ANSWER,
            errors=errors,
            **_finalize_kwargs(
                prompt_tokens_total,
                completion_tokens_total,
                start_ms,
                model,
            ),
        )

    return Text2CypherResult(
        question=question,
        status="ok",
        cypher=cypher,
        attempts=attempts,
        fixes=fixes,
        rows=rows,
        answer=answer,
        errors=errors,
        **_finalize_kwargs(
            prompt_tokens_total,
            completion_tokens_total,
            start_ms,
            model,
        ),
    )


def load_few_shots() -> list[dict]:
    """Đọc `few_shots.json` cùng thư mục với script này."""
    with FEW_SHOTS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Text2Cypher CLI — hỏi đồ thị tri thức an ninh bằng tiếng Việt."
    )
    parser.add_argument("question", nargs="?", help="Câu hỏi tiếng Việt")
    parser.add_argument("--json", action="store_true", help="In kết quả dạng JSON")
    parser.add_argument(
        "--check-model",
        action="store_true",
        help="Chỉ kiểm model có khả dụng trên gateway",
    )
    args = parser.parse_args(argv)

    try:
        cfg = load_llm_config()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    client = make_client(cfg)

    if args.check_model:
        ok, msg = check_model(client, cfg.model)
        print(f"Model {cfg.model}: {'OK' if ok else 'KHÔNG khả dụng - ' + msg}")
        return 0 if ok else 1

    if not args.question:
        parser.error("cần truyền câu hỏi, hoặc dùng --check-model")

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")

    def generate(messages: list[dict]) -> str:
        return chat(client, cfg.model, messages)

    def interpret(messages: list[dict]) -> str:
        return chat(client, cfg.model, messages)

    # `default_access_mode="READ"` CHỈ là routing hint, không phải security
    # control thật trên Neo4j Community (xem `.claude/rules/text2cypher.md`) —
    # lớp chặn ghi chính là validate 4 lớp (L1 readonly) trước khi tới đây.
    # `Query(..., timeout=...)` chỉ hỗ trợ qua `session.run`, KHÔNG hỗ trợ
    # trong transaction function của `execute_read` (đã tự verify bằng driver
    # neo4j 6.4.0 thật: `tx.run(Query(...))` raise TypeError) — nên dùng
    # `session(default_access_mode="READ")` + `session.run(Query(...))` thay
    # vì `execute_read`, để vẫn có timeout thật.
    def explain(cypher: str) -> None:
        with driver.session(default_access_mode="READ") as s:
            s.run(Query("EXPLAIN " + cypher, timeout=QUERY_TIMEOUT_SECONDS))

    def execute(cypher: str) -> list[dict]:
        # Cắt dòng NGAY TRONG lúc đọc record (itertools.islice trên Result,
        # là iterator) — không materialize toàn bộ kết quả vào RAM trước khi
        # cắt, tránh câu Cypher kiểu cartesian product (vd `MATCH (a),(b),(c)`)
        # treo máy/hết RAM.
        with driver.session(default_access_mode="READ") as s:
            result = s.run(Query(cypher, timeout=QUERY_TIMEOUT_SECONDS))
            return [dict(r) for r in itertools.islice(result, MAX_ROWS)]

    with GraphDatabase.driver(uri, auth=None) as driver:
        schema = fetch_schema(driver)
        few_shots = load_few_shots()

        result = answer_question(
            args.question,
            schema=schema,
            few_shots=few_shots,
            generate=generate,
            interpret=interpret,
            explain=explain,
            execute=execute,
        )

    if args.json:
        payload = asdict(result)
        payload["rows"] = to_jsonable(payload["rows"])
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(result.answer)

    return 0 if result.status != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
