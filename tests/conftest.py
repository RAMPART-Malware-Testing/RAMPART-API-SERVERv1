import sys
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "test-only-secret")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "postgres_integration: requires RAMPART_TEST_DATABASE_URL and uses only a temporary schema",
    )
