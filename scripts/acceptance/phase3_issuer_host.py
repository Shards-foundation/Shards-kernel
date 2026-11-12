"""Synthetic issuance on a dedicated GitHub runner; never a human-approval attestation.

The private key is generated only on this runner, outside the upload directory.
The signed permit authorises only a single harmless add(17, 25) operation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from importlib import metadata
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import shards_kernel
import operator_issuer
from phase3_protocol import canonical, make_proposal, write_new_file


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def boot_fingerprint() -> str:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(bool(boot_id), "Linux boot ID unavailable")
    return sha256(boot_id.encode("ascii")).hexdigest()


def main(handoff: Path, private_home: Path) -> int:
    require(metadata.version("shards-kernel") == "0.1.3", "Wrong wheel version")
    installed = Path(shards_kernel.__file__).resolve()
    require("site-packages" in installed.parts or "dist-packages" in installed.parts,
            "Kernel imported from checkout rather than installed PyPI wheel")
    require(private_home.resolve() != handoff.resolve(), "Signing key and handoff co-located")
    require(not private_home.resolve().is_relative_to(handoff.resolve()),
            "Private signer directory is inside shared artifact")
    handoff.mkdir(mode=0o700, parents=True, exist_ok=False)
    operator_issuer.init(private_home)
    public = (private_home / "issuer-public.bin").read_bytes()
    require(len(public) == 32, "Unexpected Ed25519 public key size")

    proposal_path = handoff / "proposal.json"
    permit_path = handoff / "permit.json"
    proposal = make_proposal("add", {"a": 17, "b": 25})
    write_new_file(proposal_path, canonical(proposal))
    # This is an AUTOMATED CONTRACT TEST. No independent human approved it.
    with patch("builtins.input", return_value="APPROVE"):
        operator_issuer.issue(private_home, proposal_path, permit_path)
    write_new_file(handoff / "issuer-public.bin", public)
    manifest = {
        "schema": "shards.phase3.cross-runner-acceptance.v1",
        "issuer_boot_sha256": boot_fingerprint(),
        "public_key_sha256": sha256(public).hexdigest(),
        "commit_sha": os.environ.get("GITHUB_SHA", "local"),
        "issuer_role": "synthetic-ci-issuer",
        "approval_type": "simulated-not-human",
        "issued_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    write_new_file(handoff / "manifest.json", canonical(manifest))
    files = {p.name for p in handoff.iterdir()}
    require(files == {"proposal.json", "permit.json", "issuer-public.bin", "manifest.json"},
            "Unexpected shared artifact or private-key leak")
    require((private_home / "issuer-private.key").is_file(), "Signer key not stored privately")
    print("CI_ISSUER_HOST: PASS (real separate runner; human approval simulated)")
    print("PUBLIC_FINGERPRINT:", manifest["public_key_sha256"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(Path(sys.argv[1]), Path(sys.argv[2])))
    except (OSError, ValueError, RuntimeError, IndexError) as exc:
        print("CI_ISSUER_HOST: FAIL:", type(exc).__name__, str(exc), file=sys.stderr)
        raise SystemExit(2)
