"""Test tích hợp cho `few_shots.json` — cần Neo4j thật đang chạy, đã nạp đủ
dữ liệu pipeline Giai đoạn 02 (158 node, 243 relationship, container `neo4j-sec`).

Dùng fixture `neo4j_driver` (session scope) có sẵn trong `tests/conftest.py`.
"""

import json
from pathlib import Path

import pytest
from schema_text import fetch_schema
from validator import validate_cypher

FEW_SHOTS_PATH = (
    Path(__file__).parent.parent / "src" / "llm" / "text2cypher" / "few_shots.json"
)

REQUIRED_COVERAGE = {
    "RUNS",
    "HAS_VULN",
    "KEV",
    "ADMIN_TO",
    "MEMBER_OF",
    "AUTHENTICATED_TO",
    "CONNECTS_TO",
    "Alert",
    "datetime",
    "count",
}


def _load_pairs() -> list[dict]:
    with FEW_SHOTS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def test_few_shots_has_10_to_15_pairs():
    pairs = _load_pairs()
    assert 10 <= len(pairs) <= 15


@pytest.mark.integration
def test_few_shots_validate_cleanly_with_no_fixes(neo4j_driver):
    """Mỗi cặp phải pass validate_cypher() (EXPLAIN thật trên Neo4j) và
    không cần fix_directions can thiệp — nghĩa là viết đúng hướng từ đầu."""
    schema = fetch_schema(neo4j_driver)
    pairs = _load_pairs()

    with neo4j_driver.session() as session:

        def explain(cypher: str) -> None:
            session.run(f"EXPLAIN {cypher}").consume()

        for pair in pairs:
            result = validate_cypher(pair["cypher"], schema, explain)
            assert result.fixes == [], (
                f"Cypher cho câu hỏi '{pair['question']}' cần fix_directions: "
                f"{result.fixes} — sửa lại cypher trong few_shots.json"
            )


@pytest.mark.integration
def test_few_shots_expect_nonempty_pairs_actually_return_rows(neo4j_driver):
    pairs = _load_pairs()

    with neo4j_driver.session() as session:
        for pair in pairs:
            if not pair.get("expect_nonempty"):
                continue
            rows = list(session.run(pair["cypher"]))
            assert len(rows) >= 1, (
                f"Cypher cho câu hỏi '{pair['question']}' expect_nonempty=true "
                f"nhưng trả về 0 dòng trên Neo4j hiện tại"
            )


def test_few_shots_covers_required_relationship_patterns():
    pairs = _load_pairs()
    all_covers: set[str] = set()
    for pair in pairs:
        all_covers |= set(pair["covers"])

    missing = REQUIRED_COVERAGE - all_covers
    assert not missing, f"Thiếu coverage: {missing}"
