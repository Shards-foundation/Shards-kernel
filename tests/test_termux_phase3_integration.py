"""Real cryptographic issuer/verifier tests for the Phase 3 Termux pilot.

Uses temporary on-disk Ed25519 keys, SQLite, StrictKernel and the actual local
memory handler. Only the human terminal confirmation and home directories are
test doubles. This does not certify physically separated operating systems.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from shards_kernel.api import Decision, ReceiptStatus

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
PHASE3 = EXAMPLES / "termux_phase3"


@pytest.fixture
def phase3(monkeypatch):
    """Use the Phase 2 module by its documented Termux import name."""
    monkeypatch.syspath_prepend(str(PHASE3))
    agent_spec = importlib.util.spec_from_file_location(
        "agent_v2", EXAMPLES / "13_termux_qwen3_governed_agent.py"
    )
    assert agent_spec is not None and agent_spec.loader is not None
    agent_v2 = importlib.util.module_from_spec(agent_spec)
    monkeypatch.setitem(sys.modules, "agent_v2", agent_v2)
    agent_spec.loader.exec_module(agent_v2)
    protocol = importlib.import_module("phase3_protocol")
    issuer = importlib.import_module("operator_issuer")
    verifier = importlib.import_module("agent_verifier_v3")
    return protocol, issuer, verifier


def _proposal_and_keys(phase3, tmp_path):
    protocol, issuer, verifier = phase3
    issuer_home = tmp_path / "issuer"
    phone_home = tmp_path / "phone"
    issuer.init(issuer_home)
    public = (issuer_home / "issuer-public.bin").read_bytes()
    verifier.enroll(phone_home, public.hex(), hashlib.sha256(public).hexdigest())
    proposal = protocol.make_proposal(
        "remember", {"key": "demo", "value": "approved"}
    )
    proposal_path = tmp_path / "proposal.json"
    protocol.write_new_file(proposal_path, protocol.canonical(proposal) + b"\n")
    return issuer_home, phone_home, proposal_path


def test_real_issuer_verifier_allow_replay_and_tamper(phase3, tmp_path, monkeypatch):
    protocol, issuer, verifier = phase3
    issuer_home, phone_home, proposal_path = _proposal_and_keys(phase3, tmp_path)
    permit_path = tmp_path / "permit.json"
    monkeypatch.setattr("builtins.input", lambda prompt: "APPROVE")
    issuer.issue(issuer_home, proposal_path, permit_path)

    original = protocol.read_json_file(permit_path)
    assert original["algorithm"] == "Ed25519"

    tampered = dict(original)
    tampered["signature"] = "00" * 64
    tampered_path = tmp_path / "tampered.json"
    protocol.write_new_file(tampered_path, protocol.canonical(tampered))
    denied = verifier.execute(phone_home, proposal_path, tampered_path)
    assert denied.decision == Decision.DENY
    assert denied.status == ReceiptStatus.REJECTED

    from_issuer = verifier.execute(phone_home, proposal_path, permit_path)
    assert from_issuer.decision == Decision.ALLOW
    assert from_issuer.status == ReceiptStatus.ACCEPTED
    assert from_issuer.tool_result == "saved"

    replay = verifier.execute(phone_home, proposal_path, permit_path)
    assert replay.decision == Decision.DENY
    assert replay.status == ReceiptStatus.REJECTED


def test_operator_denial_never_creates_permit(phase3, tmp_path, monkeypatch):
    protocol, issuer, _ = phase3
    issuer_home, _, proposal_path = _proposal_and_keys(phase3, tmp_path)
    permit_path = tmp_path / "unsigned.json"
    monkeypatch.setattr("builtins.input", lambda prompt: "NO")
    with pytest.raises(ValueError, match="declined"):
        issuer.issue(issuer_home, proposal_path, permit_path)
    assert not permit_path.exists()


def test_proposal_replaced_during_approval_is_rejected(phase3, tmp_path, monkeypatch):
    protocol, issuer, _ = phase3
    issuer_home, _, proposal_path = _proposal_and_keys(phase3, tmp_path)
    permit_path = tmp_path / "replaced-permit.json"

    def edit_after_review(prompt):
        proposal = protocol.read_json_file(proposal_path)
        proposal["params"]["value"] = "different"
        proposal_path.write_bytes(protocol.canonical(proposal))
        return "APPROVE"

    monkeypatch.setattr("builtins.input", edit_after_review)
    with pytest.raises(ValueError, match="changed during approval"):
        issuer.issue(issuer_home, proposal_path, permit_path)
    assert not permit_path.exists()


def test_enrolment_refuses_bad_fingerprint_and_key_replacement(phase3, tmp_path):
    _, issuer, verifier = phase3
    home = tmp_path / "operator"
    issuer.init(home)
    pub = (home / "issuer-public.bin").read_bytes()
    phone = tmp_path / "phone"
    with pytest.raises(ValueError, match="fingerprint"):
        verifier.enroll(phone, pub.hex(), "00" * 32)
    verifier.enroll(phone, pub.hex(), hashlib.sha256(pub).hexdigest())
    with pytest.raises(ValueError, match="already enrolled"):
        verifier.enroll(phone, pub.hex(), hashlib.sha256(pub).hexdigest())
