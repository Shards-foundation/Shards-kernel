#!/usr/bin/env python3
"""Native Android/Termux acceptance probe; never signs or self-approves permits.

Collects bounded, non-secret machine evidence. Running this on Ubuntu, inside
a Linux container or in CI must fail rather than masquerade as phone testing.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory

EXPECTED_VERSION = "0.1.3"
SOURCE_ROOT = Path(__file__).resolve().parents[2]
PHASE3_ROOT = SOURCE_ROOT / "examples" / "termux_phase3"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def native_android_evidence() -> dict:
    prefix = os.environ.get("PREFIX", "")
    require(
        prefix.startswith(("/data/data/com.termux/files/usr",
                           "/data/user/0/com.termux/files/usr")),
        "No native Termux PREFIX found; Linux/proot/CI simulation cannot pass",
    )
    getprop = Path("/system/bin/getprop")
    require(getprop.is_file() and platform.system() == "Linux",
            "Android system property service not available")
    def prop(name: str) -> str:
        result = subprocess.run(
            [str(getprop), name], capture_output=True, text=True,
            check=True, timeout=5,
        )
        return result.stdout.strip()[:32]
    sdk = prop("ro.build.version.sdk")
    release = prop("ro.build.version.release")
    require(sdk.isascii() and sdk.isdecimal() and int(sdk) >= 28,
            "Android SDK version missing or unexpectedly old")
    require(bool(release), "Android release unavailable")
    return {
        "native_termux_prefix_verified": True,
        "android_sdk": sdk,
        "android_release": release,
        "arch": platform.machine()[:32],
        "python": ".".join(map(str, sys.version_info[:3])),
        "note": "Software environment evidence only; not hardware attestation",
    }


def package_evidence() -> dict:
    import shards_kernel
    version = metadata.version("shards-kernel")
    require(version == EXPECTED_VERSION, "Wrong installed shards-kernel version")
    installed = Path(shards_kernel.__file__).resolve()
    require("site-packages" in installed.parts or "dist-packages" in installed.parts,
            "Shards-Kernel imported from a source tree, not an installed package")
    return {"wheel_version": version, "installed_distribution": "site-packages"}


def sqlite_evidence() -> dict:
    with TemporaryDirectory(prefix="shards-termux-acceptance-") as directory:
        path = Path(directory) / "audit.sqlite3"
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("CREATE TABLE event (id INTEGER PRIMARY KEY, evidence TEXT NOT NULL)")
            conn.execute("INSERT INTO event(evidence) VALUES (?)", ("persistent-event",))
            conn.commit()
        with sqlite3.connect(path) as restarted:
            result = restarted.execute("SELECT evidence FROM event WHERE id=1").fetchone()
            integrity = restarted.execute("PRAGMA integrity_check").fetchone()
        require(result == ("persistent-event",) and integrity == ("ok",),
                "SQLite restart persistence or integrity check failed")
    return {"sqlite_restart": "PASS", "sqlite_integrity": "PASS"}


def qwen_evidence() -> dict:
    sys.path.insert(0, str(PHASE3_ROOT))
    from agent_tools import _open_json, ask_model
    models = _open_json("/v1/models")
    require(type(models) is dict and type(models.get("data")) is list
            and bool(models["data"]), "No live localhost model data")
    actions = ask_model("Propose exactly one add tool action with a=17 and b=25.")
    require(actions == [("add", {"a": 17, "b": 25})],
            "Local model did not produce the expected bounded JSON proposal")
    return {"local_qwen_endpoint": "PASS", "proposal_only": "PASS",
            "model_never_executed_tool": True}


def externally_signed_execution(args) -> dict:
    require(all((args.public_key_hex, args.fingerprint, args.proposal, args.permit)),
            "Signed execution requires external public key, trusted fingerprint, proposal and permit")
    require(len(args.public_key_hex) == 64 and len(args.fingerprint) == 64,
            "Expected Ed25519 key and SHA256 fingerprint in hex")
    require(PHASE3_ROOT.is_dir(), "Phase 3 source is not present alongside probe")
    sys.path.insert(0, str(PHASE3_ROOT))
    import agent_verifier_v3 as verifier
    from shards_kernel.api import Decision, ReceiptStatus
    # Signing code is intentionally never imported, invoked or installed here.
    root = args.state_dir.expanduser()
    require(not (root / "issuer-private.key").exists(),
            "Private issuer key discovered on phone; stop and investigate")
    enrolled = root / "operator-v3.pub"
    if enrolled.exists():
        require(not enrolled.is_symlink() and enrolled.read_bytes().hex() ==
                args.public_key_hex, "Enrolled public key differs from out-of-band input")
    else:
        verifier.enroll(root, args.public_key_hex, args.fingerprint)
    result = verifier.execute(root, args.proposal, args.permit)
    require(result.decision is Decision.ALLOW and
            result.status is ReceiptStatus.ACCEPTED and result.tool_result == 42,
            "Actual Termux signed add(17,25) was not accepted")
    replay = verifier.execute(root, args.proposal, args.permit)
    require(replay.decision is Decision.DENY and
            replay.status is ReceiptStatus.REJECTED,
            "Replay was not rejected on the actual phone")
    return {"external_permit_exact_add": "PASS",
            "replay_denied": "PASS", "local_kernel_audit": "PASS",
            "private_signer_on_device": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qwen", action="store_true",
                        help="Probe the real local 127.0.0.1:8080 model")
    parser.add_argument("--execute", action="store_true",
                        help="Run a real externally signed, one-use permit on this phone")
    parser.add_argument("--public-key-hex", default="")
    parser.add_argument("--fingerprint", default="")
    parser.add_argument("--proposal", type=Path)
    parser.add_argument("--permit", type=Path)
    parser.add_argument("--state-dir", type=Path,
                        default=Path.home() / ".shards-qwen3-v3")
    parser.add_argument("--json-out", type=Path,
                        help="Create private JSON evidence file (never overwrite)")
    args = parser.parse_args()
    try:
        evidence = {
            "schema": "shards.termux.native-acceptance.v1",
            "utc": datetime.now(timezone.utc).isoformat(),
            "android": native_android_evidence(),
            "kernel": package_evidence(),
            "sqlite": sqlite_evidence(),
            "qwen": qwen_evidence() if args.qwen else "NOT_VERIFIED",
            "external_signed_execution":
                externally_signed_execution(args) if args.execute else "NOT_VERIFIED",
            "human_authority": "NOT_VERIFIED_BY_DEVICE_PROBE",
            "hardware_attestation": "NOT_VERIFIED",
        }
        evidence["result"] = (
            "PASS_DEVICE_SIGNED_EXECUTION" if args.execute and args.qwen
            else "PASS_PARTIAL_DEVICE_PROBE_ONLY"
        )
        output = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        if args.json_out:
            fd = os.open(args.json_out, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(output + "\n")
        print(output)
        return 0
    except (OSError, RuntimeError, ValueError, LookupError, subprocess.SubprocessError,
            sqlite3.Error) as exc:
        print("TERMUX_DEVICE_ACCEPTANCE: FAIL CLOSED:", type(exc).__name__,
              str(exc)[:260], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
