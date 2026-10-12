"""Test tích hợp cho `fetch_schema()` — cần Neo4j thật đang chạy, đã nạp đủ
dữ liệu pipeline Giai đoạn 02 (158 node, 243 relationship, container `neo4j-sec`).

Dùng fixture `neo4j_driver` (session scope) có sẵn trong `tests/conftest.py`.
"""

import pytest
from schema_text import fetch_schema, render_schema_text

EXPECTED_LABELS = {
    "Asset",
    "Network",
    "Service",
    "Vulnerability",
    "User",
    "Account",
    "Group",
    "Alert",
}

EXPECTED_REL_TYPES = {
    "IN_NETWORK",
    "RUNS",
    "HAS_VULN",
    "HAS_ACCOUNT",
    "MEMBER_OF",
    "ADMIN_TO",
    "CONNECTS_TO",
    "AUTHENTICATED_TO",
    "TRIGGERED_ON",
    "INVOLVES",
}

EXPECTED_PATTERNS = {
    ("Asset", "RUNS", "Service"),
    ("Service", "HAS_VULN", "Vulnerability"),
    ("Group", "ADMIN_TO", "Asset"),
    ("Asset", "CONNECTS_TO", "Asset"),
}


@pytest.mark.integration
def test_fetch_schema_returns_expected_labels_and_rel_types(neo4j_driver):
    schema = fetch_schema(neo4j_driver)

    assert set(schema.node_props) == EXPECTED_LABELS
    assert len(schema.node_props) == 8

    assert set(schema.rel_props) == EXPECTED_REL_TYPES
    assert len(schema.rel_props) == 10


@pytest.mark.integration
def test_fetch_schema_patterns_contain_expected_tuples(neo4j_driver):
    schema = fetch_schema(neo4j_driver)

    for expected in EXPECTED_PATTERNS:
        assert expected in schema.patterns


@pytest.mark.integration
def test_fetch_schema_rel_types_without_properties_still_present(neo4j_driver):
    """Rel type không property (ví dụ IN_NETWORK, RUNS, MEMBER_OF) vẫn phải có
    key trong rel_props, map rỗng — không bị thiếu."""
    schema = fetch_schema(neo4j_driver)

    for rel_type in (
        "IN_NETWORK",
        "RUNS",
        "MEMBER_OF",
        "HAS_ACCOUNT",
        "ADMIN_TO",
        "TRIGGERED_ON",
        "INVOLVES",
    ):
        assert rel_type in schema.rel_props
        assert schema.rel_props[rel_type] == {}


@pytest.mark.integration
def test_render_schema_text_is_deterministic_on_real_schema(neo4j_driver):
    first = render_schema_text(fetch_schema(neo4j_driver))
    second = render_schema_text(fetch_schema(neo4j_driver))

    assert first == second


@pytest.mark.integration
def test_render_schema_text_does_not_leak_real_data_values(neo4j_driver):
    """Schema text chỉ chứa label/property/type/pattern — không chứa giá trị
    dữ liệu thật (hostname, CVE id) đang nằm trong DB đã nạp."""
    text = render_schema_text(fetch_schema(neo4j_driver))

    # Vài giá trị dữ liệu thật biết chắc có trong DB demo (hostname/CVE mẫu).
    # Nếu hàm render lỡ nối giá trị dữ liệu thay vì tên property, các chuỗi
    # này sẽ xuất hiện — không được xuất hiện ở đây.
    forbidden_substrings = ["CVE-", "web-01", "db-01"]
    for forbidden in forbidden_substrings:
        assert forbidden not in text
