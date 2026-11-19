"""Cross-runner verifier: imports no private signer and receives no private key.

Verifier runs on another GitHub-hosted VM. Artifact transfer is real, but
public-key custody and human approval are CI simulations, not production proof.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from importlib import metadata
import json
import os
from pathlib import Path
import sys

import shards_kernel
from shards_kernel.api import Decision, ReceiptStatus
import agent_verifier_v3 as verifier
from phase3_protocol import canonical, read_json_file, write_new_file


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def boot_fingerprint() -> str:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(bool(boot_id), "Linux boot ID unavailable")
    return sha256(boot_id.encode("ascii")).hexdigest()


def main(handoff: Path, verifier_home: Path, evidence_path: Path) -> int:
    require(metadata.version("shards-kernel") == "0.1.3", "Wrong wheel version")
    installed = Path(shards_kernel.__file__).resolve()
    require("site-packages" in installed.parts or "dist-packages" in installed.parts,
            "Kernel imported from checkout rather than installed PyPI wheel")
    require(not (Path(__file__).parent / "operator_issuer.py").exists(),
            "Private issuer module must not be copied onto verifier host")
    require({p.name for p in handoff.iterdir()} ==
            {"proposal.json", "permit.json", "issuer-public.bin", "manifest.json"},
            "Unexpected files in verifier input")
    for location in (handoff, verifier_home, Path(__file__).parent):
        require(not (location / "issuer-private.key").exists(),
                "Private signing key reached verifier")
    manifest = read_json_file(handoff / "manifest.json")
    require(manifest["schema"] == "shards.phase3.cross-runner-acceptance.v1",
            "Wrong artifact envelope")
    require(manifest["approval_type"] == "simulated-not-human",
            "Synthetic test must not claim human approval")
    require(manifest["commit_sha"] == os.environ.get("GITHUB_SHA", "local"),
            "Artifact came from a different commit")
    require(manifest["issuer_boot_sha256"] != boot_fingerprint(),
            "Verifier and issuer share the same operating-system boot")
    public = (handoff / "issuer-public.bin").read_bytes()
    require(len(public) == 32, "Invalid public key")
    fingerprint = sha256(public).hexdigest()
    require(fingerprint == manifest["public_key_sha256"], "Public-key mismatch")
    require(fingerprint == os.environ.get("EXPECTED_ISSUER_FINGERPRINT"),
            "Public fingerprint did not match independent job output")
    verifier.enroll(verifier_home, public.hex(), fingerprint)

    proposal_path = handoff / "proposal.json"
    permit_path = handoff / "permit.json"
    altered = read_json_file(proposal_path)
    altered["params"] = {"a": 17, "b": 26}
    tampered_path = verifier_home / "tampered-proposal.json"
    write_new_file(tampered_path, canonical(altered))
    tamper_denied = False
    try:
        verifier.execute(verifier_home, tampered_path, permit_path)
    except ValueError as exc:
        tamper_denied = "Signed permit does not match exact proposal" in str(exc)
    require(tamper_denied, "Mismatched signed proposal was not rejected")

    result = verifier.execute(verifier_home, proposal_path, permit_path)
    require(result.decision is Decision.ALLOW and result.status is ReceiptStatus.ACCEPTED,
            "Approved harmless operation not accepted")
    require(result.tool_result == 42, "Incorrect authorised tool result")
    replay = verifier.execute(verifier_home, proposal_path, permit_path)
    require(replay.decision is Decision.DENY and replay.status is ReceiptStatus.REJECTED,
            "Previously consumed permit was not denied")

    evidence = {
        "schema": "shards.phase3.cross-runner-evidence.v1",
        "commit_sha": os.environ.get("GITHUB_SHA", "local"),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "issuer_boot_sha256": manifest["issuer_boot_sha256"],
        "verifier_boot_sha256": boot_fingerprint(),
        "different_os_boot_ids": True,
        "public_key_sha256": fingerprint,
        "published_package": metadata.version("shards-kernel"),
        "human_approval": "NOT_VERIFIED",
        "real_external_service": "NOT_VERIFIED",
        "physical_android_termux": "NOT_VERIFIED",
        "tampered_proposal": "DENY",
        "approved_add": 42,
        "permit_replay": "DENY",
        "local_audit": "PASS",
        "result": "PASS_EPHEMERAL_CROSS_RUNNER_PILOT_ONLY",
    }
    write_new_file(evidence_path, canonical(evidence) + b"\n")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])))
    except (OSError, ValueError, RuntimeError, IndexError, KeyError) as exc:
        print("CI_VERIFIER_HOST: FAIL:", type(exc).__name__, str(exc), file=sys.stderr)
        raise SystemExit(2)
