"""Validate 4 lớp cho Cypher do LLM sinh ra (Text2Cypher).

Neo4j Community không có RBAC, `execute_read` không phải security control thật
(xem `.claude/rules/security.md`) — nên 4 lớp dưới đây là lớp chính thực tế
chặn ghi/injection, không phải lớp phụ như thiết kế lý tưởng ban đầu.

Thứ tự: L1 readonly (regex sau khi bỏ comment/string literal) -> L2 syntax
(EXPLAIN) -> L3 schema (label/relType có thật) -> L4 direction (tự sửa chiều
relationship sai theo schema.patterns, rồi EXPLAIN lại nếu có sửa).
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from schema_text import GraphSchema

Layer = Literal["readonly", "syntax", "schema", "direction"]

# Clause/keyword ghi hoặc đổi state DB — chặn tuyệt đối trong Cypher chỉ-đọc.
_WRITE_KEYWORDS = [
    "CREATE",
    "MERGE",
    "DETACH DELETE",
    "DELETE",
    "SET",
    "REMOVE",
    "DROP",
    "LOAD CSV",
    "FOREACH",
    "USE",
    "GRANT",
    "DENY",
    "REVOKE",
    "ALTER",
    "START",
    "STOP",
    "TERMINATE",
    "INSERT",  # GQL synonym của CREATE, Neo4j 5.26 parse được
    "SHOW",  # SHOW PROCEDURES/SETTINGS/TRANSACTIONS... có thể lộ config server/query session khác
]

_WRITE_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(kw.replace(" ", r"\s+") for kw in _WRITE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# CALL có tên procedure theo sau (dbms.x, apoc.x, gds.x, db.x, ...) — chặn vì
# allowlist GDS write/mutate rỗng theo security.md. `CALL { ... }` subquery
# (không có tên ngay sau CALL, mà là dấu `{`) không bị chặn ở đây. Tên procedure
# có thể viết dạng backtick-quoted (vd `` `db`.`labels`() ``) — cho phép backtick
# trong character class để không lọt qua lớp chặn này.
_CALL_PROCEDURE_RE = re.compile(r"\bCALL\s+(?!\{)[`a-zA-Z_][\w.`]*", re.IGNORECASE)

# `CALL { ... } IN TRANSACTIONS` — batch write, chặn dù subquery trong {} chỉ đọc.
_IN_TRANSACTIONS_RE = re.compile(r"\bIN\s+TRANSACTIONS\b", re.IGNORECASE)

_RETURN_RE = re.compile(r"\bRETURN\b", re.IGNORECASE)

_BRACKET_RE = re.compile(r"\[[^\]]*\]")
# Chỉ coi `[...]` là bracket relationship khi đứng ngay sau `-`/`<-` (cú pháp
# cạnh quan hệ `-[:REL]->`/`<-[:REL]-`) — tránh nhầm `[...]` của list literal/
# list comprehension (vd `[n IN nodes(p) WHERE n:Asset | n.hostname]`) thành
# relType rồi báo sai "Relationship type không tồn tại: Asset".
_REL_BRACKET_RE = re.compile(r"<?-\[[^\]]*\]->?")
_BRACE_RE = re.compile(r"\{[^{}]*\}")
# Tên label/relType có thể viết dạng backtick-quoted (vd `MATCH (n:`LoadMeta`)`) —
# group(1) khớp tên backtick-quoted, group(2) khớp tên thường; dùng
# `_label_or_reltype_name(match)` để lấy tên thật bất kể dạng nào.
_LABEL_OR_RELTYPE_RE = re.compile(r":\s*(?:`([^`]*)`|([A-Za-z_][A-Za-z0-9_]*))")


def _label_or_reltype_name(match: re.Match) -> str:
    return match.group(1) if match.group(1) is not None else match.group(2)


class ValidationError(Exception):
    def __init__(self, layer: Layer, message: str):
        self.layer = layer
        self.message = message
        super().__init__(message)


@dataclass
class ValidationResult:
    cypher: str  # câu cuối cùng (đã sửa hướng nếu L4 có sửa)
    fixes: list[str]  # mô tả các lần L4 đã tự sửa, rỗng nếu không sửa gì


def _strip_comments_and_strings(cypher: str) -> str:
    """Bỏ comment (// dòng, /* */ nhiều dòng) và nội dung trong string literal
    (' ' hoặc " ") trước khi quét regex — tránh chặn nhầm 'SET' trong chuỗi
    "r.status = 'set'" hay hostname 'create-01'. Mỗi vùng bị bỏ được thay bằng
    ĐÚNG MỘT khoảng trắng (không xóa hẳn) — nếu xóa hẳn, hai từ khóa đứng cạnh
    comment/string sẽ dính liền (vd `n/**/DETACH/**/DELETE/**/n` xóa hẳn thành
    `nDETACHDELETEn`, mất word boundary, lọt qua `\\b...\\b`) — bug đã phát hiện
    khi LLM/kẻ tấn công chèn comment rỗng để né lớp readonly.

    Backtick-quoted identifier (`` `tên` ``, Cypher cho phép đặt tên biến/label
    chứa ký tự đặc biệt, escape backtick literal bằng cách viết đôi `` `` ``
    bên trong — đã tự verify cú pháp thật trên Neo4j 5.26) PHẢI được nhận diện
    NGUYÊN VẸN là 1 vùng opaque thứ 4 (cùng cấp string/comment) — nếu không,
    ký tự `'`/`"`/`//`/`/*` nằm BÊN TRONG backtick (vd tên biến hợp lệ `` `'` ``)
    bị hiểu lầm là mở string/comment THẬT, "ăn" mất code thật phía sau cho tới
    quote/newline tiếp theo — xóa mất từ khóa SET/DETACH DELETE thật (bug do
    reviewer phát hiện ở vòng 2, qua cơ chế khác với bug comment vòng 1).

    Khác với string/comment (thay bằng 1 khoảng trắng), backtick region được
    GIỮ NGUYÊN toàn bộ (gồm cả 2 backtick) trong output — `_CALL_PROCEDURE_RE`
    cần thấy `` `db`.`labels` `` để chặn đúng CALL backtick-quoted.

    Backtick MỒ CÔI (không có backtick đóng, vd 1 dấu `` ` `` lẻ cuối chuỗi)
    KHÔNG được coi là mở vùng opaque — nếu coi là mở, toàn bộ phần còn lại của
    chuỗi (không có backtick đóng để dừng) bị "ăn" nguyên vẹn làm vùng opaque,
    ẩn luôn mọi từ khóa ghi thật phía sau. Trường hợp này backtick lẻ được coi
    như 1 ký tự thường, quét tiếp bình thường."""
    result = []
    i = 0
    n = len(cypher)
    while i < n:
        two = cypher[i : i + 2]
        if two == "//":
            j = cypher.find("\n", i)
            result.append(" ")
            if j == -1:
                break
            i = j
            continue
        if two == "/*":
            j = cypher.find("*/", i + 2)
            result.append(" ")
            i = n if j == -1 else j + 2
            continue
        ch = cypher[i]
        if ch == "`":
            j = i + 1
            closed = False
            while j < n:
                if cypher[j] == "`":
                    if j + 1 < n and cypher[j + 1] == "`":
                        j += 2  # backtick đôi = 1 backtick literal trong tên, chưa đóng
                        continue
                    j += 1  # backtick đơn: đóng vùng, bao gồm luôn backtick đóng
                    closed = True
                    break
                j += 1
            if closed:
                result.append(
                    cypher[i:j]
                )  # giữ nguyên nguyên vẹn cả 2 backtick + nội dung
                i = j
            else:
                # backtick mồ côi — không coi là mở vùng, tránh "ăn" hết code
                # thật còn lại phía sau.
                result.append(ch)
                i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            j = i + 1
            while j < n and cypher[j] != quote:
                if cypher[j] == "\\":
                    j += 1
                j += 1
            result.append(" ")
            i = min(j + 1, n)
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def check_readonly(cypher: str) -> None:
    """L1 — lớp CHÍNH chặn ghi/injection."""
    cleaned = _strip_comments_and_strings(cypher)

    match = _WRITE_KEYWORD_RE.search(cleaned)
    if match:
        raise ValidationError(
            "readonly", f"Clause ghi bị chặn: {match.group(1).upper()}"
        )

    match = _CALL_PROCEDURE_RE.search(cleaned)
    if match:
        raise ValidationError(
            "readonly",
            f"CALL procedure bị chặn (không trong allowlist): {match.group(0)}",
        )

    if _IN_TRANSACTIONS_RE.search(cleaned):
        raise ValidationError("readonly", "'CALL {...} IN TRANSACTIONS' bị chặn")

    if ";" in cleaned.strip().rstrip(";"):
        raise ValidationError("readonly", "Nhiều statement nối bằng ';' bị chặn")

    if not _RETURN_RE.search(cleaned):
        raise ValidationError("readonly", "Câu không có clause RETURN bị chặn")


def check_syntax(cypher: str, explain: Callable[[str], None]) -> None:
    """L2 — gọi explain(cypher), bắt lỗi và raise ValidationError(layer="syntax", ...)."""
    try:
        explain(cypher)
    except Exception as exc:
        raise ValidationError("syntax", str(exc)) from exc


def check_schema(cypher: str, schema: GraphSchema) -> None:
    """L3 — kiểm label/relType dùng trong cypher có trong schema không.

    RelType nằm trong `[...]` (vd `[:HAS_VULN]`), label nằm ngoài `[...]`
    (vd `(v:Vulnerability)`) — tách riêng để kiểm đúng tập hợp lệ. Tên có thể
    viết dạng backtick-quoted (vd `` (n:`LoadMeta`) ``) — `_LABEL_OR_RELTYPE_RE`
    nhận cả 2 dạng, lấy tên thật qua `_label_or_reltype_name()`.

    Property map `{...}` (vd `{kev: true}`, `{status: 'open'}`) bị xóa trước khi
    quét label/relType — nếu không, key:value không quote (số/bool) như
    `{kev: true}` bị regex hiểu lầm `true` là tên label/relType (bug đã phát
    hiện ở T015 khi viết few_shots.json).

    Known limitation: `_BRACE_RE` xóa toàn bộ nội dung bên trong `{...}` trước
    khi quét — nếu LLM giấu một pattern quan hệ/label sai bên trong subquery
    dạng `EXISTS { (a)-[:FAKE_REL]->(:FakeLabel) }`, nội dung đó bị xóa cùng
    `{}` nên KHÔNG được kiểm ở layer này. Không phải lỗ hổng ghi/injection (L1
    readonly vẫn chặn write/CALL độc lập với layer này), chỉ là lỗ hổng validate
    "tên không tồn tại" bị bỏ sót trong trường hợp hiếm này — chưa sửa vì cần
    parser lồng nhau phức tạp hơn regex hiện tại, chấp nhận rủi ro thấp."""
    cleaned = _BRACE_RE.sub(" ", _strip_comments_and_strings(cypher))

    for rel_match in _REL_BRACKET_RE.finditer(cleaned):
        bracket_text = _BRACKET_RE.search(rel_match.group(0)).group(0)
        for match in _LABEL_OR_RELTYPE_RE.finditer(bracket_text):
            rel_type = _label_or_reltype_name(match)
            if rel_type not in schema.rel_props:
                raise ValidationError(
                    "schema",
                    f"Relationship type không tồn tại trong schema: {rel_type}. "
                    f"RelType hợp lệ: {sorted(schema.rel_props)}",
                )

    outside_rel_brackets = _REL_BRACKET_RE.sub(" ", cleaned)
    for match in _LABEL_OR_RELTYPE_RE.finditer(outside_rel_brackets):
        label = _label_or_reltype_name(match)
        if label not in schema.node_props:
            raise ValidationError(
                "schema",
                f"Label không tồn tại trong schema: {label}. "
                f"Label hợp lệ: {sorted(schema.node_props)}",
            )


_FORWARD_HOP_RE = re.compile(
    r"\(([^()]*?:(\w+)[^()]*?)\)\s*-\[([^\]]*?:(\w+)[^\]]*?)\]->\s*\(([^()]*?:(\w+)[^()]*?)\)"
)


def fix_directions(cypher: str, schema: GraphSchema) -> tuple[str, list[str]]:
    """L4 — tự sửa chiều relationship nếu cypher viết ngược so với schema.patterns.

    Không dùng `re.sub` một lần (non-overlapping): trong chuỗi nhiều hop liên
    tiếp (vd `(a)-[:R1]->(b)-[:R2]->(c)`), match hop1 "ăn" hết `(a)-[:R1]->(b)`,
    khiến node `(b)` dùng chung với hop2 không còn để `(b)-[:R2]->(c)` được
    xét trong CÙNG lần quét — bug đã phát hiện (chỉ sửa được hop đầu).

    Thay vào đó, tự quét tuần tự bằng `search(pos)` rồi sau mỗi hop, tiếp tục
    quét lại TỪ VỊ TRÍ NODE ĐÍCH (dst) của hop đó — cho hop kế tiếp (dùng dst
    làm src) có cơ hội được xét. Lật hướng không đổi độ dài chuỗi
    (`-[...]->` và `<-[...]-` cùng 3 ký tự ngoài bracket) nên vị trí tuyệt đối
    trong `current` vẫn đúng sau khi ghép lại."""
    fixes: list[str] = []
    current = cypher
    pos = 0

    while True:
        m = _FORWARD_HOP_RE.search(current, pos)
        if m is None:
            break

        src_full, src_label, rel_full, rel_type, dst_full, dst_label = m.groups()
        pattern = (src_label, rel_type, dst_label)
        reverse_pattern = (dst_label, rel_type, src_label)

        dst_open_paren = m.start(5) - 1

        if pattern not in schema.patterns and reverse_pattern in schema.patterns:
            fixes.append(
                f"Lật hướng {rel_type}: ({src_label})-[:{rel_type}]->({dst_label}) "
                f"-> ({src_label})<-[:{rel_type}]-({dst_label})"
            )
            replacement = f"({src_full})<-[{rel_full}]-({dst_full})"
            current = current[: m.start()] + replacement + current[m.end() :]

        pos = dst_open_paren

    return current, fixes


def validate_cypher(
    cypher: str, schema: GraphSchema, explain: Callable[[str], None]
) -> ValidationResult:
    """Chạy đủ 4 lớp theo thứ tự, raise sớm nếu L1-L3 fail."""
    check_readonly(cypher)
    check_syntax(cypher, explain)
    check_schema(cypher, schema)
    fixed_cypher, fixes = fix_directions(cypher, schema)

    if fixes:
        check_syntax(fixed_cypher, explain)

    return ValidationResult(cypher=fixed_cypher, fixes=fixes)
