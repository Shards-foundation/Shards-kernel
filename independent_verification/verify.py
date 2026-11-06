"""External verification of the installed, immutable shards-kernel 0.1.2 wheel.

Run from a directory outside the source checkout, with the published wheel
installed. This intentionally records defects; it does not modify the package.
"""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel import KernelConfig, KernelRequest, PermitBuilder, PermitToken, StrictKernel, ToolCall, VirtualClock
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PublicVerificationKey

KID = "independent-v012"
WHEEL_SHA256 = "08dc0df1ade8769a3c9cd7560fd22362e1a313aa78de5d1063c67d64a59fa057"


def credentials():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def sign(private, params=None, uses=1):
    unsigned = (PermitBuilder().issuer("lab-issuer").subject("lab-agent")
                .jurisdiction("default").action("sink")
                .params({"marker": "approved"} if params is None else params)
                .constraints({}).max_executions(uses).valid_from_ms(0)
                .valid_until_ms(10**12).proposal_hash("lab-proposal")
                .evidence_hash("").build_unsigned_v2(key_id="lab-key", audience=KID))
    return sign_v2_permit(unsigned, private)


def make_kernel(public, audit=None):
    if audit:
        from implementations.storage import SQLiteAuditStorage
        kernel = StrictKernel(SQLiteAuditStorage(str(audit)))
    else:
        kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id=KID, variant="strict", clock=VirtualClock(1000)))
    kernel.set_public_verifiers({"lab-key": PublicVerificationKey("lab-issuer", KID, public)})
    return kernel


def req(n, params=None):
    p = {"marker": "approved"} if params is None else params
    return KernelRequest("test-" + str(n), 1000, "lab-agent", "Record marker",
                         ToolCall("sink", dict(p)), dict(p))


def scope():
    private, public = credentials()
    cases = []
    for name, signed_params, submitted in (
        ("control", {"marker": "approved"}, {"marker": "approved"}),
        ("omitted", {"marker": "approved"}, {}),
        ("null_omitted", {"x": None}, {}),
    ):
        effects = []
        kernel = make_kernel(public)
        kernel._dispatcher.registry.register("sink", lambda **kwargs: effects.append(kwargs))
        receipt = kernel.submit(req(name, submitted), sign(private, signed_params))
        cases.append({"name": name, "decision": receipt.decision.value,
                      "error": receipt.error, "effects": effects})
    return {"id": "SK-002", "cases": cases,
            "omission_executed": any(x["effects"] for x in cases[1:])}


def concurrency():
    private, public = credentials()
    scenarios = []
    for limit in (1, 2, 5, 10):
        kernel = make_kernel(public)
        effects = []
        lock = threading.Lock()
        def sink(marker):
            with lock:
                effects.append(marker)
            time.sleep(0.001)
            return marker
        kernel._dispatcher.registry.register("sink", sink)
        permit = sign(private, uses=limit)
        def attempt(i):
            try:
                r = kernel.submit(req(i), permit)
                return {"decision": r.decision.value, "error": r.error}
            except Exception as exc:
                return {"exception": type(exc).__name__, "detail": str(exc)}
        with ThreadPoolExecutor(max_workers=100) as executor:
            answers = list(executor.map(attempt, range(1000)))
        allows = sum(a.get("decision") == "ALLOW" for a in answers)
        errors = [a for a in answers if "exception" in a]
        scenarios.append({"limit": limit, "attempts": 1000, "max_workers": 100,
                          "allow_receipts": allows, "effects": len(effects),
                          "exceptions": len(errors), "examples": errors[:3],
                          "overconsumed": allows > limit or len(effects) > limit})
    return {"id": "SK-001", "cases": scenarios}


def count(db):
    with sqlite3.connect(db) as con:
        return con.execute("SELECT count(*) FROM effects").fetchone()[0]


def worker(args):
    token = PermitToken(**json.loads(Path(args[0]).read_text()))
    public = bytes.fromhex(Path(args[1]).read_text())
    effects_db = Path(args[2])
    audit = Path(args[4]) if args[3] == "sqlite" else None
    kernel = make_kernel(public, audit)
    def sink(marker):
        with sqlite3.connect(effects_db) as con:
            con.execute("INSERT INTO effects(marker) VALUES (?)", (marker,))
        if args[5] == "kill":
            os.kill(os.getpid(), signal.SIGKILL)
        return marker
    kernel._dispatcher.registry.register("sink", sink)
    receipt = kernel.submit(req("recovery"), token)
    print(json.dumps({"decision": receipt.decision.value, "error": receipt.error}), flush=True)


def crash():
    private, public = credentials()
    token = sign(private)
    cases = []
    for mode in ("memory", "sqlite"):
        with tempfile.TemporaryDirectory(prefix="shards-v012-crash-") as t:
            root = Path(t)
            permit_file, key_file = root / "permit.json", root / "public.hex"
            effects_db, audit_db = root / "effects.sqlite", root / "audit.sqlite"
            permit_file.write_text(json.dumps(asdict(token)))
            key_file.write_text(public.hex())
            with sqlite3.connect(effects_db) as con:
                con.execute("CREATE TABLE effects (id INTEGER PRIMARY KEY, marker TEXT)")
            argv = [sys.executable, str(Path(__file__).resolve()), "--worker",
                    str(permit_file), str(key_file), str(effects_db), mode, str(audit_db)]
            first = subprocess.run(argv + ["kill"], capture_output=True, text=True, timeout=20)
            before = count(effects_db)
            second = subprocess.run(argv + ["retry"], capture_output=True, text=True, timeout=20)
            after = count(effects_db)
            try:
                retry = json.loads(second.stdout.strip())
            except ValueError:
                retry = {"stdout": second.stdout[-400:], "stderr": second.stderr[-400:]}
            cases.append({"mode": mode, "sigkill_exit": first.returncode,
                          "effects_after_kill": before, "effects_after_retry": after,
                          "retry_exit": second.returncode, "retry": retry,
                          "valid_crash": first.returncode == -signal.SIGKILL and before == 1 and second.returncode == 0})
    return {"id": "SK-003", "cases": cases}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2:])
        return
    import shards_kernel
    assert shards_kernel.__version__ == "0.1.2"
    assert "site-packages" in str(Path(shards_kernel.__file__).resolve()), "Must test installed wheel"
    report = {"package": "shards-kernel==0.1.2", "wheel_sha256": WHEEL_SHA256,
              "python": sys.version, "probes": []}
    for name, fn in (("scope", scope), ("concurrency", concurrency), ("crash", crash)):
        try:
            report["probes"].append(fn())
        except Exception as exc:
            report["probes"].append({"id": name, "harness_error": type(exc).__name__ + ": " + str(exc)})
    output = Path(os.environ.get("CERT_OUTPUT", "independent-results.json"))
    output.write_text(json.dumps(report, indent=2, sort_keys=True))
    print("Evidence written to", output)


if __name__ == "__main__":
    main()
