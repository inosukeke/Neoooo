"""Unit test cho schema_text.py: render tất định + không rò giá trị dữ liệu.

Dùng GraphSchema giả dựng tay — không cần Neo4j thật.
"""

from schema_text import GraphSchema, fetch_schema, render_schema_text


def _sample_schema() -> GraphSchema:
    return GraphSchema(
        node_props={
            "Asset": {
                "canonical_id": ["STRING"],
                "hostname": ["STRING"],
            },
            "Service": {
                "name": ["STRING"],
                "port": ["INTEGER"],
            },
        },
        rel_props={
            "RUNS": {},
        },
        patterns=frozenset(
            {
                ("Asset", "RUNS", "Service"),
            }
        ),
    )


def test_render_schema_text_is_deterministic():
    schema = _sample_schema()
    first = render_schema_text(schema)
    second = render_schema_text(schema)
    assert first == second


def test_render_schema_text_contains_labels_and_patterns():
    schema = _sample_schema()
    text = render_schema_text(schema)
    assert "Asset" in text
    assert "Service" in text
    assert "canonical_id" in text
    assert "(Asset)-[:RUNS]->(Service)" in text


def test_render_schema_text_only_renders_from_structured_fields():
    """Property name trùng dạng 'giá trị' (ví dụ hostname mẫu) vẫn hiện vì đó
    là TÊN property (cấu trúc), không phải giá trị dữ liệu thật — hàm không
    nhận input nào khác ngoài node_props/rel_props/patterns nên không có
    đường nào để giá trị dữ liệu thật lẫn vào output.
    """
    schema = GraphSchema(
        node_props={
            "Asset": {
                "web-01": ["STRING"],  # property NAME cố tình đặt giống hostname mẫu
            }
        },
        rel_props={},
        patterns=frozenset(),
    )
    text = render_schema_text(schema)
    assert "web-01" in text  # chỉ vì đó là tên property, không phải giá trị bị lẫn vào


def test_render_schema_text_sorts_alphabetically():
    schema = GraphSchema(
        node_props={
            "Zebra": {"z_prop": ["STRING"], "a_prop": ["STRING"]},
            "Apple": {"only": ["STRING"]},
        },
        rel_props={
            "Z_REL": {},
            "A_REL": {},
        },
        patterns=frozenset(),
    )
    text = render_schema_text(schema)
    assert text.index("Apple") < text.index("Zebra")
    assert text.index("a_prop") < text.index("z_prop")
    assert text.index("A_REL") < text.index("Z_REL")


def test_fetch_schema_signature():
    # fetch_schema đã implement thật ở T014 (xem tests/test_schema_text_integration.py cho test
    # hành vi thật trên Neo4j) — ở đây chỉ kiểm signature/default param không đổi.
    import inspect

    sig = inspect.signature(fetch_schema)
    assert list(sig.parameters) == ["driver", "database"]
    assert sig.parameters["database"].default == "neo4j"
