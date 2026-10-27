"""Unit test cho validator.py: 4 lớp validate Cypher do LLM sinh ra.

Không cần Neo4j thật — `explain` được giả lập bằng hàm Python (no-op để pass
L2, hoặc raise Exception để test fail L2). GraphSchema giả dựng tay.
"""

import pytest

from secgraph.llm.text2cypher.schema_text import GraphSchema
from secgraph.llm.text2cypher.validator import (
    ValidationError,
    check_readonly,
    check_schema,
    check_syntax,
    fix_directions,
    validate_cypher,
)


def _noop_explain(cypher: str) -> None:
    pass


def _sample_schema() -> GraphSchema:
    return GraphSchema(
        node_props={
            "Asset": {"hostname": ["STRING"]},
            "Vulnerability": {"cve_id": ["STRING"]},
            "Service": {"name": ["STRING"]},
        },
        rel_props={
            "RUNS": {},
            "HAS_VULN": {},
        },
        patterns=frozenset(
            {
                ("Asset", "RUNS", "Service"),
                ("Service", "HAS_VULN", "Vulnerability"),
            }
        ),
    )


# --- check_readonly: chặn write clause ---


@pytest.mark.parametrize(
    "cypher",
    [
        "MATCH (a:Asset) CREATE (b:Asset) RETURN a",
        "MATCH (a:Asset) MERGE (b:Asset {id: 1}) RETURN a",
        "MATCH (a:Asset) DELETE a RETURN a",
        "MATCH (a:Asset) DETACH DELETE a RETURN a",
        "MATCH (a:Asset) SET a.x = 1 RETURN a",
        "MATCH (a:Asset) REMOVE a.x RETURN a",
        "DROP INDEX foo",
        "LOAD CSV FROM 'file:///x.csv' AS row RETURN row",
        "MATCH (a) FOREACH (x IN [1,2] | SET a.y = x) RETURN a",
        "USE neo4j MATCH (a) RETURN a",
        "GRANT MATCH {*} ON GRAPH * TO role",
        "DENY WRITE ON GRAPH * TO role",
        "REVOKE ROLE role FROM user",
        "ALTER USER foo SET PASSWORD 'bar'",
        "START n=node(1) RETURN n",
        "STOP TRANSACTION 'id'",
        "TERMINATE TRANSACTION 'id'",
        "CALL dbms.components() RETURN *",
        "CALL apoc.periodic.iterate('a', 'b', {}) RETURN *",
        "CALL gds.pageRank.write('g', {}) RETURN *",
        "CALL db.labels() RETURN *",
        "CALL { MATCH (a) RETURN a } IN TRANSACTIONS RETURN *",
        "MATCH (a) RETURN a; MATCH (b) RETURN b",
        # chen comment/xuống dòng để test regex không bị né bằng comment
        "MATCH (a:Asset)\n// comment\nCREATE (b) RETURN a",
        "MATCH (a:Asset) /* c */ set a.x = 1 RETURN a",
        # bypass case do reviewer phát hiện: comment rỗng `/**/` chen GIỮA 2 từ
        # của 1 keyword nhiều từ (hoặc giữa CALL và tên procedure) — nếu
        # `_strip_comments_and_strings` xóa hẳn comment (không thay bằng
        # khoảng trắng) thì 2 token dính liền mất word boundary, lọt `\b...\b`.
        "MATCH (n) WITH n/**/DETACH/**/DELETE/**/n RETURN count(*) AS c",
        "MATCH (a:Asset) WITH a/**/SET a.hostname = 1 RETURN a.hostname",
        "CALL/**/db.labels() YIELD label RETURN label",
        # INSERT là GQL synonym của CREATE, Neo4j 5.26 parse được — phải chặn.
        "INSERT (x:Asset {canonical_id: 1}) RETURN x",
        # CALL với tên procedure backtick-quoted — regex gốc chỉ nhận
        # [a-zA-Z_][\\w.]* (không có backtick) nên lọt qua.
        "CALL `db`.`labels`() YIELD label RETURN label",
        # SHOW có thể lộ config server/query session khác (SHOW PROCEDURES/
        # SETTINGS/TRANSACTIONS...) — reviewer tự chạy thật xác nhận lọt qua.
        "SHOW PROCEDURES YIELD name RETURN name",
        "SHOW SETTINGS",
        "SHOW TRANSACTIONS",
        # --- BLOCKER vòng 2: backtick-quoted identifier chứa ký tự đặc biệt
        # ('/"/'//'/'/*') bị hiểu lầm là mở string/comment THẬT, "ăn" mất từ
        # khóa ghi thật phía sau. 2 case reviewer tự verify + 10 case stress-
        # test tự viết thêm (biến thể: comment-opener trong backtick, nhiều
        # cặp backtick liên tiếp, escape backtick đôi, backtick mồ côi,
        # backtick trong string thường, CALL backtick có khoảng trắng, ';'
        # trong backtick...).
        "MATCH (n:Asset {hostname:'x'}) WITH n AS `'` SET `'`.pwned = true RETURN `'`.hostname",
        "MATCH (n) WITH n AS `'` DETACH DELETE `'` RETURN 1 AS `'`",
        "MATCH (n) WITH n AS `/*` DETACH DELETE n RETURN 1",
        "MATCH (n) WITH n AS `//` SET n.x = 1 RETURN n",
        "MATCH (n) WITH n AS `a`, n AS `'` SET n.y = 1 RETURN n",
        "MATCH (n) WITH n AS `a``b` DELETE n RETURN 1",
        "MATCH (n) WITH n AS `x`/* c */DROP INDEX foo",
        "MATCH (n) WHERE n.name = 'a`b' CREATE (m) RETURN n",
        "MATCH (n) WITH n AS ` REMOVE n.x RETURN n",
        "CALL `my proc`() YIELD x RETURN x",
        "MATCH (n) WITH n AS `a``b` MERGE (m) RETURN n",
        "MATCH (n) WITH n AS `;` DETACH DELETE n RETURN 1",
    ],
)
def test_check_readonly_blocks_write_clauses(cypher):
    with pytest.raises(ValidationError) as exc_info:
        check_readonly(cypher)
    assert exc_info.value.layer == "readonly"


@pytest.mark.parametrize(
    "cypher",
    [
        "MATCH (a:Asset) WHERE a.hostname = 'create-01' RETURN a",
        "MATCH (r) WHERE r.status = 'set' RETURN r",
        "MATCH (a:Asset) RETURN count(a) AS asset_count",
        "CALL { MATCH (a) RETURN a } RETURN *",
    ],
)
def test_check_readonly_does_not_false_positive(cypher):
    check_readonly(cypher)  # không raise


def test_check_readonly_blocks_missing_return():
    with pytest.raises(ValidationError) as exc_info:
        check_readonly("MATCH (a:Asset) WHERE a.hostname = 'x'")
    assert exc_info.value.layer == "readonly"


# --- check_syntax ---


def test_check_syntax_raises_on_explain_error():
    def _bad_explain(cypher: str) -> None:
        raise RuntimeError("syntax error near MATCH")

    with pytest.raises(ValidationError) as exc_info:
        check_syntax("MATCH (a) RETURN a", _bad_explain)
    assert exc_info.value.layer == "syntax"
    assert "syntax error" in exc_info.value.message


def test_check_syntax_passes_when_explain_ok():
    check_syntax("MATCH (a) RETURN a", _noop_explain)  # không raise


# --- check_schema ---


def test_check_schema_rejects_unknown_label():
    schema = _sample_schema()
    with pytest.raises(ValidationError) as exc_info:
        check_schema("MATCH (a:UnknownLabel) RETURN a", schema)
    assert exc_info.value.layer == "schema"


def test_check_schema_rejects_unknown_rel_type():
    schema = _sample_schema()
    with pytest.raises(ValidationError) as exc_info:
        check_schema("MATCH (a:Asset)-[:UNKNOWN_REL]->(s:Service) RETURN a", schema)
    assert exc_info.value.layer == "schema"


def test_check_schema_passes_known_label_and_rel_type():
    schema = _sample_schema()
    check_schema("MATCH (a:Asset)-[:RUNS]->(s:Service) RETURN a", schema)  # không raise


def test_check_schema_accepts_backtick_quoted_label():
    """Minor do reviewer phát hiện: `:\\`LoadMeta\\`` (label backtick-quoted,
    vd đặt tên trùng từ khóa hoặc chứa ký tự đặc biệt) phải được nhận diện
    đúng tên thật, không bị coi là "không tồn tại" một cách sai."""
    schema = GraphSchema(
        node_props={"LoadMeta": {"value": ["STRING"]}},
        rel_props={},
        patterns=frozenset(),
    )
    check_schema("MATCH (n:`LoadMeta`) RETURN n.value", schema)  # không raise

    with pytest.raises(ValidationError) as exc_info:
        check_schema("MATCH (n:`NotExist`) RETURN n", schema)
    assert exc_info.value.layer == "schema"


def test_check_schema_does_not_treat_list_comprehension_bracket_as_rel_type():
    """Bug do reviewer phát hiện: `[...]` không đứng sau `-`/`<-` (list
    comprehension) từng bị quét lẫn vào relType -> báo sai "Asset" không tồn
    tại trong relType, trong khi đây là label hợp lệ trong `n:Asset`."""
    schema = _sample_schema()
    check_schema(
        "MATCH p = (a:Asset) RETURN [n IN nodes(p) WHERE n:Asset | n.hostname] AS hosts",
        schema,
    )  # không raise


# --- fix_directions ---


def test_fix_directions_flips_reversed_relationship():
    schema = _sample_schema()
    cypher = "MATCH (v:Vulnerability)-[:HAS_VULN]->(s:Service) RETURN v"
    fixed, fixes = fix_directions(cypher, schema)
    assert fixed == "MATCH (v:Vulnerability)<-[:HAS_VULN]-(s:Service) RETURN v"
    assert len(fixes) == 1


def test_fix_directions_no_change_when_pattern_matches():
    schema = _sample_schema()
    cypher = "MATCH (a:Asset)-[:RUNS]->(s:Service) RETURN a"
    fixed, fixes = fix_directions(cypher, schema)
    assert fixed == cypher
    assert fixes == []


def test_fix_directions_no_change_when_pattern_unknown():
    schema = _sample_schema()
    cypher = "MATCH (a:Asset)-[:NOPE]->(s:Service) RETURN a"
    fixed, _fixes = fix_directions(cypher, schema)
    assert fixed == cypher


def test_fix_directions_fixes_second_hop_in_multi_hop_chain():
    """Bug do reviewer phát hiện: 1 lần `sub` duy nhất chỉ sửa được hop đầu
    trong chuỗi nhiều hop (match hop1 "ăn" hết `(a:A)-[:R1]->(b:B)`, khiến
    `(b:B)-[:R2]->(c:C)` không được xét trong CÙNG lần quét). `fix_directions`
    phải lặp tới fixed-point để hop2 cũng được sửa."""
    schema = GraphSchema(
        node_props={"A": {}, "B": {}, "C": {}},
        rel_props={"R1": {}, "R2": {}},
        patterns=frozenset({("A", "R1", "B"), ("C", "R2", "B")}),
    )
    cypher = "MATCH (a:A)-[:R1]->(b:B)-[:R2]->(c:C) RETURN a, b, c"
    fixed, fixes = fix_directions(cypher, schema)
    assert fixed == "MATCH (a:A)-[:R1]->(b:B)<-[:R2]-(c:C) RETURN a, b, c"
    assert len(fixes) == 1


# --- validate_cypher: tích hợp cả 4 lớp ---


def test_validate_cypher_fixes_direction_and_passes():
    schema = _sample_schema()
    cypher = "MATCH (v:Vulnerability)-[:HAS_VULN]->(s:Service) RETURN v"
    result = validate_cypher(cypher, schema, _noop_explain)
    assert result.cypher == "MATCH (v:Vulnerability)<-[:HAS_VULN]-(s:Service) RETURN v"
    assert len(result.fixes) == 1


def test_validate_cypher_raises_readonly_before_others():
    schema = _sample_schema()
    with pytest.raises(ValidationError) as exc_info:
        validate_cypher("MATCH (a:Asset) CREATE (b) RETURN a", schema, _noop_explain)
    assert exc_info.value.layer == "readonly"


def test_validate_cypher_raises_schema_error():
    schema = _sample_schema()
    with pytest.raises(ValidationError) as exc_info:
        validate_cypher("MATCH (a:UnknownLabel) RETURN a", schema, _noop_explain)
    assert exc_info.value.layer == "schema"
