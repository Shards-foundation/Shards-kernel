"""Published v0.1.3 PostgreSQL cross-OS-process and crash tests.

Uses only a disposable SHARDS_TEST_POSTGRES_DSN. No external provider effects.
"""

import multiprocessing as mp
import os
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.common.types import KernelConfig, KernelRequest, ToolCall, VirtualClock
from shards_kernel.distributed.postgres import PostgresPermitJournal
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey
from shards_kernel.variants.strict_kernel import StrictKernel


AUDIENCE = "published-acceptance-operator"
KEY_ID = "acceptance-issuer"


def require(condition, reason):
    """Always enforce test invariants, even under python -O."""
    if not condition:
        raise AssertionError(reason)


def require_disposable_database(value):
    """Refuse arbitrary or remote database targets before schema modification."""
    require(
        os.environ.get("SHARDS_ACCEPTANCE_DISPOSABLE_DB") == "YES_TEST_ONLY",
        "Explicit disposable-database opt-in required",
    )
    require(bool(value), "Missing SHARDS_TEST_POSTGRES_DSN")
    require(
        not any(os.environ.get(name) for name in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE")),
        "libpq environment connection overrides are forbidden",
    )
    config = conninfo_to_dict(value)
    require(
        not any(key in config for key in ("hostaddr", "service", "servicefile")),
        "PostgreSQL connection redirection overrides are forbidden",
    )
    dbname = config.get("dbname", "")
    host = config.get("host", "")
    require(isinstance(host, str) and "," not in host, "Multiple PostgreSQL hosts forbidden")
    require(
        dbname in ("shards_acceptance", "shards_kernel_test"),
        "Only named disposable acceptance/test databases may be used",
    )
    require(
        host in ("localhost", "127.0.0.1") or host.startswith("/"),
        "Remote PostgreSQL targets are prohibited by this acceptance harness",
    )
    return value


def journal(dsn):
    return PostgresPermitJournal(lambda: psycopg.connect(dsn, connect_timeout=5))


@pytest.fixture(scope="module")
def dsn():
    value = os.environ.get("SHARDS_TEST_POSTGRES_DSN")
    require_disposable_database(value)
    journal(value).initialize_schema()
    return value


def contender(dsn, permit, public_key, start, results):
    try:
        kernel = StrictKernel()
        kernel.enable_shared_permit_accounting(journal(dsn))
        kernel.boot(KernelConfig(
            kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)
        ))
        kernel.set_policy(JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}),
            allowed_tools=frozenset({"echo"}),
        ))
        kernel.set_public_verifiers({KEY_ID: PublicVerificationKey(
            issuer="operator", audience=AUDIENCE, public_key=public_key,
        )})
        request = KernelRequest(
            request_id=uuid4().hex, ts_ms=1000, actor="alice",
            intent="test external process permit budget",
            tool_call=ToolCall(name="echo", params={"text": "approved"}),
            params={"text": "approved"},
        )
        start.wait(timeout=20)
        receipt = kernel.submit(request, permit_token=permit)
        results.put((receipt.decision.value, receipt.tool_result))
    except Exception as exc:
        results.put(("ERROR", repr(exc)))


def test_two_os_processes_share_one_authority(dsn):
    ctx = mp.get_context("spawn")
    for _ in range(5):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes_raw()
        permit = sign_v2_permit((
            PermitBuilder().issuer("operator").subject("alice")
            .jurisdiction("default").action("echo")
            .params({"text": "approved"}).constraints({})
            .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
            .proposal_hash("acceptance")
            .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
        ), key)
        start = ctx.Barrier(2)
        results = ctx.Queue()
        children = [
            ctx.Process(target=contender, args=(dsn, permit, public, start, results))
            for _ in range(2)
        ]
        try:
            for child in children:
                child.start()
            for child in children:
                child.join(timeout=30)
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=5)
                    pytest.fail("Process contention worker timed out")
                require(child.exitcode == 0, f"Contender exited {child.exitcode}")
            outcomes = [results.get(timeout=5) for _ in children]
            require(sum(d == "ALLOW" and value == "approved" for d, value in outcomes) == 1, f"Not exactly one allowed effect: {outcomes}")
            require(sum(d == "DENY" and value is None for d, value in outcomes) == 1, f"Not exactly one denied request: {outcomes}")
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=5)
            results.close()
            results.join_thread()


def dying_worker(dsn, values, dispatch):
    store = journal(dsn)
    reserved = store.reserve(
        operation_id=values["operation_id"], permit_id=values["permit_id"],
        issuer=values["issuer"], subject=values["subject"],
        nonce=values["nonce"], max_executions=1,
        request_sha256="b" * 64,
    )
    if not reserved:
        os._exit(78)
    if dispatch and not store.mark_dispatched(values["operation_id"]):
        os._exit(79)
    # Simulated process death after the database COMMIT, not a remote effect.
    os._exit(77)


@pytest.mark.parametrize("dispatch", [False, True], ids=["reserved", "dispatched"])
def test_crash_retains_budget_and_quarantines_uncertainty(dsn, dispatch):
    ctx = mp.get_context("spawn")
    for _ in range(3):
        values = {
            "operation_id": uuid4().hex, "permit_id": uuid4().hex,
            "issuer": "acceptance-operator", "subject": "acceptance-agent",
            "nonce": uuid4().hex,
        }
        child = ctx.Process(target=dying_worker, args=(dsn, values, dispatch))
        child.start()
        child.join(timeout=30)
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
            pytest.fail("Crash worker timed out")
        require(child.exitcode == 77, f"Crash worker exited {child.exitcode}")
        store = journal(dsn)
        record = store.get(values["operation_id"])
        require(record is not None, "Committed operation missing")
        require(record.state == ("DISPATCHED" if dispatch else "RESERVED"), "Incorrect crash state")
        require(store.reserve(
            operation_id=uuid4().hex, permit_id=values["permit_id"],
            issuer=values["issuer"], subject=values["subject"],
            nonce=values["nonce"], max_executions=1, request_sha256="b" * 64,
        ) is False, "Consumed permit was reserved again")
        if dispatch:
            require(store.mark_unknown(values["operation_id"]) is True, "Quarantine rejected")
            require(store.get(values["operation_id"]).state == "UNKNOWN", "Incorrect quarantine state")
        with psycopg.connect(dsn) as conn:
            budget = conn.execute(
                "SELECT used, max_executions FROM shards_permit_budget "
                "WHERE issuer=%s AND subject=%s AND nonce=%s",
                (values["issuer"], values["subject"], values["nonce"]),
            ).fetchone()
        require(budget == (1, 1), f"Permit budget corrupted: {budget}")
