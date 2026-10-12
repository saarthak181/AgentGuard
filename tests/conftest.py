import pytest

from agent import tools
from backend.database import configure_database


@pytest.fixture(autouse=True)
def isolate_agentguard_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    configure_database(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


@pytest.fixture
def documents(tmp_path, monkeypatch):
    root = tmp_path / "document"
    root.mkdir()
    monkeypatch.setattr(tools, "DOCUMENT_DIR", root)
    (root / "sales_report.txt").write_text(
        "January: 12000\nFebruary: 15000\nMarch: 18000\nApril: 21000\nBest region: North India\n", encoding="utf-8"
    )
    return root
