"""Fail-closed PostgreSQL target preflight for all copied acceptance modules.

This module becomes conftest.py only when staged into the isolated test directory so the frozen v0.1.3
tests cannot connect to an accidentally supplied production DSN.
"""

import os

import pytest
from psycopg.conninfo import conninfo_to_dict


def pytest_sessionstart(session):
    """Stop before test collection or fixtures can write to a database."""
    if os.environ.get("SHARDS_ACCEPTANCE_DISPOSABLE_DB") != "YES_TEST_ONLY":
        pytest.exit("Disposable database opt-in missing", returncode=2)
    dsn = os.environ.get("SHARDS_TEST_POSTGRES_DSN", "")
    if not dsn:
        pytest.exit("Disposable PostgreSQL DSN missing", returncode=2)
    if any(os.environ.get(name) for name in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE")):
        pytest.exit("Refusing libpq environment connection overrides", returncode=2)
    try:
        settings = conninfo_to_dict(dsn)
    except Exception:
        pytest.exit("Invalid PostgreSQL DSN", returncode=2)
    if any(key in settings for key in ("hostaddr", "service", "servicefile")):
        pytest.exit("Refusing PostgreSQL connection overrides", returncode=2)
    database = settings.get("dbname", "")
    host = settings.get("host", "")
    if not isinstance(host, str) or "," in host:
        pytest.exit("Refusing multi-host or missing PostgreSQL target", returncode=2)
    if database not in ("shards_acceptance", "shards_kernel_test"):
        pytest.exit("Refusing non-test PostgreSQL database", returncode=2)
    if host not in ("127.0.0.1", "localhost") and not host.startswith("/"):
        pytest.exit("Refusing remote PostgreSQL database", returncode=2)
