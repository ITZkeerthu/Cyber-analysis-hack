import sys
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base  # noqa: E402
from app.graph_engine import GraphEngine  # noqa: E402
from app.models import Evidence  # noqa: E402


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _add(db, path):
    db.add(Evidence(
        case_id="C1", timestamp=datetime(2026, 1, 5, 12, 0), user="alice",
        ip_address="10.0.0.1", device="pc1", file_path=path, action="read", raw_data={},
    ))
    db.commit()


def _file_ids(graph):
    return {n["id"] for n in graph["nodes"] if n["id"].startswith("file_")}


def test_empty_case_returns_empty_graph(db):
    graph = GraphEngine(db).build_graph("missing")
    assert graph["nodes"] == [] and graph["edges"] == []


def test_file_node_ids_are_stable_across_builds(db):
    _add(db, "/etc/passwd")
    first = _file_ids(GraphEngine(db).build_graph("C1"))
    second = _file_ids(GraphEngine(db).build_graph("C1"))
    assert len(first) == 1
    assert first == second


def test_distinct_files_get_distinct_nodes(db):
    paths = [f"/data/file_{i}.txt" for i in range(200)]
    for p in paths:
        _add(db, p)
    assert len(_file_ids(GraphEngine(db).build_graph("C1"))) == len(paths)
