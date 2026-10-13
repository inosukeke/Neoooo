"""Unit test cho src/llm/text2cypher/prompts.py — to_jsonable() với các
neo4j.time / neo4j.spatial types (S5.4). Không cần DB — chỉ test format."""

import neo4j.time as neo4j_time
from prompts import to_jsonable


# ---------- neo4j.time temporal types ----------
def test_to_jsonable_datetime_iso():
    val = neo4j_time.DateTime(2026, 10, 5, 12, 30, 45, 123456789)
    result = to_jsonable(val)
    assert isinstance(result, str)
    assert "2026-10-05" in result
    assert "T" in result


def test_to_jsonable_date_iso():
    val = neo4j_time.Date(2026, 10, 5)
    result = to_jsonable(val)
    assert result == "2026-10-05"


def test_to_jsonable_time_iso():
    val = neo4j_time.Time(12, 30, 45)
    result = to_jsonable(val)
    assert "12:30:45" in result


def test_to_jsonable_duration_iso():
    val = neo4j_time.Duration(years=1, months=6, days=15, hours=12)
    result = to_jsonable(val)
    # ISO 8601 duration format: P1Y6M15DT12H
    assert result.startswith("P")
    assert "Y" in result  # year component


def test_to_jsonable_temporal_nested_in_list():
    """List chứa temporal type — phải đệ quy qua list nhánh."""
    val = [
        neo4j_time.DateTime(2026, 10, 5, 0, 0, 0),
        neo4j_time.Date(2026, 10, 6),
    ]
    result = to_jsonable(val)
    assert isinstance(result, list)
    assert "2026-10-05T" in result[0]
    assert result[1] == "2026-10-06"


def test_to_jsonable_temporal_nested_in_dict():
    """Dict value là temporal — phải đệ quy qua dict nhánh."""
    val = {"created_at": neo4j_time.DateTime(2026, 10, 5, 0, 0, 0)}
    result = to_jsonable(val)
    assert "2026-10-05T" in result["created_at"]


# ---------- list[float] (Neo4j vector index returns) ----------
def test_to_jsonable_list_of_floats_passthrough():
    """Vector index của Neo4j 5.x trả list[float] qua RETURN — passthrough."""
    val = [0.1, 0.2, 0.3]
    result = to_jsonable(val)
    assert result == [0.1, 0.2, 0.3]


# ---------- Fallback cho unknown type ----------
def test_unknown_type_falls_back_to_str():
    """Type lạ không match bất kỳ nhánh nào — fallback str() (không crash)."""

    class Weird:
        def __str__(self):
            return "<weird>"

    assert to_jsonable(Weird()) == "<weird>"


# ---------- Edge cases đệ quy ----------
def test_to_jsonable_deeply_nested():
    """Đệ quy sâu dict + list + primitive — không stack overflow, không crash."""
    val = {"a": [{"b": [{"c": "deep"}]}]}
    assert to_jsonable(val) == val


def test_to_jsonable_with_none_values():
    """None trong dict/list phải giữ nguyên (không thành 'None' string)."""
    val = {"a": None, "b": [None, 1, "x"]}
    result = to_jsonable(val)
    assert result == {"a": None, "b": [None, 1, "x"]}


def test_to_jsonable_bool_preserved():
    """True/False phải là bool JSON, không thành 'True' string."""
    assert to_jsonable(True) is True
    assert to_jsonable(False) is False
    assert to_jsonable([True, False, 0, 1]) == [True, False, 0, 1]