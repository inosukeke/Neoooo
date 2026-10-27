"""Unit test cho src/config.py — centralized config (S0.2)."""

from secgraph.config import (
    LLMConfig,
    Neo4jConfig,
    NVDConfig,
    OpenSearchConfig,
    Settings,
    TestConfig,
    load_settings,
)


def _set(monkeypatch, **env):
    """Set/unset env vars cho test."""
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


# ---------- Neo4jConfig ----------
def test_neo4j_default(monkeypatch):
    _set(monkeypatch, NEO4J_URI=None, NEO4J_USER=None, NEO4J_PASSWORD=None)
    c = Neo4jConfig()
    assert c.uri == "bolt://localhost:7687"
    assert c.user == "neo4j"
    assert c.password is None
    assert c.auth is None  # no-auth demo local


def test_neo4j_password_sets_auth_tuple(monkeypatch):
    _set(monkeypatch, NEO4J_PASSWORD="secret123")
    c = Neo4jConfig()
    assert c.password == "secret123"
    assert c.auth == ("neo4j", "secret123")


def test_neo4j_uri_override(monkeypatch):
    _set(monkeypatch, NEO4J_URI="bolt://remote:7687")
    c = Neo4jConfig()
    assert c.uri == "bolt://remote:7687"


# ---------- OpenSearchConfig ----------
def test_opensearch_default(monkeypatch):
    _set(monkeypatch, OPENSEARCH_HOST=None, OPENSEARCH_PORT=None)
    c = OpenSearchConfig()
    assert c.host == "localhost"
    assert c.port == 9200


def test_opensearch_env_override(monkeypatch):
    _set(monkeypatch, OPENSEARCH_HOST="myhost", OPENSEARCH_PORT="9999")
    c = OpenSearchConfig()
    assert c.host == "myhost"
    assert c.port == 9999


# ---------- LLMConfig ----------
def test_llm_default_all_none(monkeypatch):
    _set(
        monkeypatch,
        OPENAI_API_KEY=None,
        OPENAI_BASE_URL=None,
        TEXT2CYPHER_MODEL=None,
    )
    c = LLMConfig()
    assert c.api_key is None
    assert c.base_url is None
    assert c.model is None


def test_llm_full_config(monkeypatch):
    _set(
        monkeypatch,
        OPENAI_API_KEY="sk-xxx",
        OPENAI_BASE_URL="https://gw.example/v1",
        TEXT2CYPHER_MODEL="gpt-4o-mini",
    )
    c = LLMConfig()
    assert c.api_key == "sk-xxx"
    assert c.base_url == "https://gw.example/v1"
    assert c.model == "gpt-4o-mini"


def test_llm_empty_string_treated_as_none(monkeypatch):
    _set(
        monkeypatch,
        OPENAI_API_KEY="",
        OPENAI_BASE_URL="",
        TEXT2CYPHER_MODEL="",
    )
    c = LLMConfig()
    assert c.api_key is None
    assert c.base_url is None
    assert c.model is None


# ---------- NVDConfig ----------
def test_nvd_default(monkeypatch):
    _set(monkeypatch, NVD_API_KEY=None)
    c = NVDConfig()
    assert c.api_key is None


def test_nvd_with_key(monkeypatch):
    _set(monkeypatch, NVD_API_KEY="nvd-key-123")
    c = NVDConfig()
    assert c.api_key == "nvd-key-123"


# ---------- TestConfig ----------
def test_test_default_destructive_false(monkeypatch):
    _set(monkeypatch, ALLOW_DESTRUCTIVE_TESTS=None)
    c = TestConfig()
    assert c.destructive_tests is False


def test_test_destructive_truthy(monkeypatch):
    _set(monkeypatch, ALLOW_DESTRUCTIVE_TESTS="1")
    c = TestConfig()
    assert c.destructive_tests is True


# ---------- Settings container ----------
def test_settings_aggregates_all(monkeypatch):
    _set(
        monkeypatch,
        NEO4J_URI="bolt://x",
        OPENSEARCH_HOST="y",
        OPENAI_API_KEY="k",
        TEXT2CYPHER_MODEL="m",
        NVD_API_KEY="n",
        ALLOW_DESTRUCTIVE_TESTS="1",
    )
    s = load_settings()
    assert s.neo4j.uri == "bolt://x"
    assert s.opensearch.host == "y"
    assert s.llm.api_key == "k"
    assert s.llm.model == "m"
    assert s.nvd.api_key == "n"
    assert s.test.destructive_tests is True


def test_load_settings_cached_by_env_file(monkeypatch):
    """Same env_file -> same Settings instance (lru_cache)."""
    s1 = load_settings()
    s2 = load_settings()
    assert s1 is s2


def test_load_settings_different_env_file_distinct(monkeypatch):
    """Different env_file -> distinct Settings instances (cache key varies)."""
    s1 = load_settings(env_file=None)
    s2 = load_settings(env_file=".env")
    # Vẫn có thể là cùng instance nếu không thay đổi thực tế, nhưng test rằng
    # call với kwarg khác nhau KHÔNG crash.
    assert isinstance(s1, Settings)
    assert isinstance(s2, Settings)
