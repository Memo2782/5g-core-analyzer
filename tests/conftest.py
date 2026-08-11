import pytest
import os

from core.database import init_db

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_5g_analyzer.db")


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()
    yield


pytest_plugins = ["pytest_asyncio"]
