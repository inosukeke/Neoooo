"""Unit test cho src/llm/text2cypher/prompts.py — extract_cypher() edge cases
(S5.3). Không gọi LLM thật — test logic regex."""

from prompts import extract_cypher


def test_extract_strips_cypher_fence():
    """Fence ```cypher ... ``` — case phổ biến nhất (LLM trả với `cypher` tag)."""
    text = "Đây là câu trả lời:\n```cypher\nMATCH (n) RETURN n\n```"
    assert extract_cypher(text) == "MATCH (n) RETURN n"


def test_extract_strips_generic_fence():
    """Fence ``` ... ``` không có `cypher` tag (LLM đôi khi bỏ tag)."""
    text = "```\nMATCH (n:Asset) RETURN n\n```"
    assert extract_cypher(text) == "MATCH (n:Asset) RETURN n"


def test_extract_returns_raw_when_no_fence():
    """LLM trả thẳng Cypher không có fence — regex không match, trả text.strip()."""
    text = "MATCH (n:Asset) RETURN n.hostname"
    assert extract_cypher(text) == "MATCH (n:Asset) RETURN n.hostname"


def test_extract_with_leading_text():
    """LLM có thể trả 'Sure, here's the query:' trước fence — regex lấy fence đầu tiên."""
    text = "Sure, here's the query:\n```cypher\nMATCH (n) RETURN n\n```"
    assert extract_cypher(text) == "MATCH (n) RETURN n"


def test_extract_with_trailing_text():
    """LLM có thể giải thích sau fence — regex chỉ lấy fence đầu tiên, bỏ phần sau."""
    text = (
        "```cypher\nMATCH (n) RETURN n\n```\n"
        "Câu query trên trả về tất cả node trong đồ thị."
    )
    assert extract_cypher(text) == "MATCH (n) RETURN n"


def test_extract_strips_whitespace():
    """Fence có newline thừa trước/sau Cypher — strip trước khi trả."""
    text = "```cypher\n\n   MATCH (n) RETURN n   \n\n```"
    assert extract_cypher(text) == "MATCH (n) RETURN n"


def test_extract_multiline_cypher():
    """Cypher multi-line trong fence — DOTALL flag phải match."""
    text = (
        "```cypher\n"
        "MATCH (a:Asset)\n"
        "WHERE a.hostname = 'web-01'\n"
        "RETURN a.hostname, a.ip\n"
        "```"
    )
    assert (
        extract_cypher(text)
        == "MATCH (a:Asset)\nWHERE a.hostname = 'web-01'\nRETURN a.hostname, a.ip"
    )


def test_extract_returns_full_text_when_only_one_fence_delimiter():
    """Bug edge case: chỉ có 1 backtick fence (mở mà không đóng) — regex match.group(1)
    greedy với DOTALL có thể trả rỗng. Hiện tại regex yêu cầu CẢ 3 backticks đóng
    nên không match nếu thiếu — text.strip() trả nguyên."""
    text = "MATCH (n) RETURN n\n```"
    # Không có cặp fence đầy đủ → không match regex → trả text.strip()
    assert extract_cypher(text) == "MATCH (n) RETURN n\n```"


def test_extract_no_match_returns_empty_string_for_empty_input():
    """Empty input → empty string."""
    assert extract_cypher("") == ""
    assert extract_cypher("   \n  ") == ""


def test_extract_case_insensitive_fence_tag():
    """Fence tag `CYPHER` (uppercase) cũng match (regex có IGNORECASE)."""
    text = "```CYPHER\nMATCH (n) RETURN n\n```"
    assert extract_cypher(text) == "MATCH (n) RETURN n"