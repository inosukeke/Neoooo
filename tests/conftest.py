"""Fixture dùng chung cho test integration (Neo4j/OpenSearch thật)."""

import os

import pytest


@pytest.fixture(scope="session")
def neo4j_driver():
    from neo4j import GraphDatabase

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")
    auth = (user, password) if password else None
    driver = GraphDatabase.driver(uri, auth=auth)
    yield driver
    driver.close()


@pytest.fixture(scope="session")
def os_client():
    from secgraph.search.os_client import make_client

    return make_client()
