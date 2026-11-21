"""Shared test environment: an isolated SQLite database and local storage per run."""
import os
import sys
from pathlib import Path

import pytest

TEST_ROOT = Path(f"/tmp/securesign-tests-{os.getpid()}")
for key, value in {
    "DATABASE_URL": f"sqlite:///{TEST_ROOT / 'test.db'}",
    "SECURESIGN_STORAGE_DIR": str(TEST_ROOT / "storage"),
    "ADMIN_EMAIL": "root@example.com",
    "ADMIN_PASSWORD": "test-admin-password-very-long",
    "ADMIN_NAME": "Test Admin",
    "COOKIE_SECURE": "false",
    "APP_ENV": "development",
    "REQUIRE_EMAIL_VERIFICATION": "false",
    "SECURESIGN_LAB_ENABLED": "true",
    "TRUST_PROXY_HEADERS": "false",
    "SECURESIGN_DEMO_ACCOUNTS": "false",   # tests create their own users; demo seeding is tested directly
}.items():
    os.environ.setdefault(key, value)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Every test starts with empty in-memory rate-limit buckets."""
    from backend.app import main
    main._RATE_BUCKETS.clear()
    yield
