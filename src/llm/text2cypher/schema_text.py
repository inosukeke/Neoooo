"""Cấu trúc đại diện schema đồ thị Neo4j + render thành text tất định.

Dùng chung cho:
- Sinh schema text chèn vào prompt LLM (bước 1 pipeline Text2Cypher).
- Lớp validate "schema check" (T009).

`render_schema_text` CHỈ đọc từ `GraphSchema` (node_props/rel_props/patterns) —
không nhận thêm input nào khác, không chứa giá trị dữ liệu thật (hostname, CVE id...).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class GraphSchema:
    node_props: dict[
        str, dict[str, list[str]]
    ]  # label -> {propertyName: [propertyTypes]}
    rel_props: dict[
        str, dict[str, list[str]]
    ]  # relType -> {propertyName: [propertyTypes]}
    patterns: frozenset[tuple[str, str, str]]  # (src_label, rel_type, dst_label)


def render_schema_text(schema: GraphSchema) -> str:
    """Render GraphSchema thành text tất định (sort alphabet mọi cấp)."""
    lines: list[str] = []

    lines.append("Node labels:")
    for label in sorted(schema.node_props):
        props = schema.node_props[label]
        prop_text = ", ".join(
            f"{name} ({'/'.join(sorted(types))})"
            for name, types in sorted(props.items())
        )
        lines.append(f"- {label}: {prop_text}")

    lines.append("Relationship types:")
    for rel_type in sorted(schema.rel_props):
        props = schema.rel_props[rel_type]
        prop_text = ", ".join(
            f"{name} ({'/'.join(sorted(types))})"
            for name, types in sorted(props.items())
        )
        lines.append(f"- {rel_type}: {prop_text}" if prop_text else f"- {rel_type}:")

    lines.append("Patterns:")
    for src, rel_type, dst in sorted(schema.patterns):
        lines.append(f"- ({src})-[:{rel_type}]->({dst})")

    return "\n".join(lines)


def fetch_schema(driver, database: str = "neo4j") -> GraphSchema:
    """Chạy `db.schema.nodeTypeProperties()`/`relTypeProperties()` + 1 query pattern
    trên Neo4j thật để build `GraphSchema`.

    Tên cột xác nhận thật trên Neo4j 5.26 (container `neo4j-sec`, GDS 2.13.13):
    - `db.schema.nodeTypeProperties()`: nodeType, nodeLabels (list[str]),
      propertyName, propertyTypes (list[str], ví dụ `["String"]`/`["Long"]`),
      mandatory. Mỗi node ở dự án này chỉ 1 label → lấy `nodeLabels[0]`.
    - `db.schema.relTypeProperties()`: relType, propertyName, propertyTypes, mandatory.
      Rel type không property (ví dụ `IN_NETWORK`, `RUNS`, `MEMBER_OF`) trả về
      đúng 1 dòng với `propertyName=None`, `propertyTypes=None` — bỏ qua dòng
      đó khi build map nhưng vẫn phải đảm bảo `rel_props` có key cho rel type
      đó (map rỗng `{}`).
    """
    # Internal nodes (loader/kỹ thuật, không thuộc Schema v2 nghiệp vụ) theo
    # convention: prefix `_` (LoadMeta sẽ đổi tên thành `_LoadMeta` ở commit
    # tương ứng, hoặc node tương lai như `_SchemaVersion` cũng tự filter).
    # Cùng nguyên tắc load_graph.py đã loại trừ `LoadMeta` khỏi
    # EXPECT_NODES/verify_counts/warn_stale.

    node_props: dict[str, dict[str, list[str]]] = {}
    with driver.session(database=database) as session:
        for record in session.run("CALL db.schema.nodeTypeProperties()"):
            label = record["nodeLabels"][0]
            if label.startswith("_"):
                continue
            prop_name = record["propertyName"]
            prop_types = record["propertyTypes"]
            props = node_props.setdefault(label, {})
            if prop_name is not None:
                props[prop_name] = list(prop_types)

        rel_props: dict[str, dict[str, list[str]]] = {}
        for record in session.run("CALL db.schema.relTypeProperties()"):
            rel_type = record["relType"].strip(":`")
            props = rel_props.setdefault(rel_type, {})
            prop_name = record["propertyName"]
            prop_types = record["propertyTypes"]
            if prop_name is not None:
                props[prop_name] = list(prop_types)

        patterns: set[tuple[str, str, str]] = set()
        pattern_query = (
            "MATCH (a)-[r]->(b) "
            "RETURN DISTINCT labels(a)[0] AS s, type(r) AS t, labels(b)[0] AS d"
        )
        for record in session.run(pattern_query):
            s, t, d = record["s"], record["t"], record["d"]
            if s.startswith("_") or d.startswith("_"):
                continue
            patterns.add((s, t, d))

    return GraphSchema(
        node_props=node_props,
        rel_props=rel_props,
        patterns=frozenset(patterns),
    )
