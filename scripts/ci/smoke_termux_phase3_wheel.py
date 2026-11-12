"""Clean-room acceptance for Phase 3 against the exact published PyPI wheel.

Run this copied to a temporary directory, outside the repository checkout,
with a clean venv holding only shards-kernel[crypto]==0.1.3. All Phase 3
modules are copied beside it. Signing/verification run locally here, so this
does not establish independent OS/host isolation.
"""
from __future__ import annotations

from hashlib import sha256
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import shards_kernel
from shards_kernel.api import Decision, ReceiptStatus

import phase3_protocol as protocol
import operator_issuer as issuer
import agent_verifier_v3 as verifier


def require(condition: bool, message: str) -> None:
    """Enforce acceptance invariants even under python -O."""
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    installed = Path(shards_kernel.__file__).resolve()
    require(metadata.version("shards-kernel") == "0.1.3", "Published wheel version mismatch")
    require("site-packages" in installed.parts or "dist-packages" in installed.parts,
            "Kernel imported from source checkout instead of installed wheel")
    with TemporaryDirectory(prefix="shards-phase3-wheel-") as temp:
        operator_home = Path(temp) / "operator"
        agent_home = Path(temp) / "agent"
        issuer.init(operator_home)
        public = (operator_home / "issuer-public.bin").read_bytes()
        verifier.enroll(agent_home, public.hex(), sha256(public).hexdigest())

        proposal = protocol.make_proposal("add", {"a": 17, "b": 25})
        proposal_file = Path(temp) / "proposal.json"
        signed_file = Path(temp) / "permit.json"
        protocol.write_new_file(proposal_file, protocol.canonical(proposal))
        with patch("builtins.input", return_value="APPROVE"):
            issuer.issue(operator_home, proposal_file, signed_file)

        result = verifier.execute(agent_home, proposal_file, signed_file)
        require(result.decision is Decision.ALLOW, f"Expected ALLOW: {result!r}")
        require(result.status is ReceiptStatus.ACCEPTED, f"Expected ACCEPTED: {result!r}")
        require(result.tool_result == 42, f"Expected 42: {result!r}")
        repeated = verifier.execute(agent_home, proposal_file, signed_file)
        require(repeated.decision is Decision.DENY, f"Expected replay DENY: {repeated!r}")
        require(repeated.status is ReceiptStatus.REJECTED, f"Expected replay REJECTED: {repeated!r}")
    print("PHASE3_PUBLISHED_WHEEL_SMOKE: PASS (issuer/verifier locally simulated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
