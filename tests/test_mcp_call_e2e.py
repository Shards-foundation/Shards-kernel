"""Public agent-facing CLI against a real independently signed operator/MCP process."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("mcp")
from shards_kernel.cli.mcp_call import main  # noqa: E402
from tests.test_mcp_agent_relay import (  # noqa: E402
    _fixture,
    _sign_permit,
    _start_service,
    _stop,
)


@pytest.mark.skipif(os.name != "posix", reason="Local SQLite operator and permit file need POSIX")
def test_agent_cli_executes_real_signed_mcp_once_and_denies_replay(
    tmp_path, monkeypatch, capsys
):
    """Proof from user CLI through official SDK stdio to real signed operator."""
    config, policy, issuer, alpha, _beta = _fixture(tmp_path, monkeypatch)
    args = {"text": "agent-demo-live"}
    permit = _sign_permit(issuer, "agent-alpha", "echo", args)
    permit_path = tmp_path / "independently-issued-v2-permit.json"
    permit_path.write_text(json.dumps(permit), encoding="utf-8")
    permit_path.chmod(0o600)

    # The agent only holds its separately enrolled token. The trusted policy
    # issuer/permit signing keys remain in the separate test parent.
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_TOKEN", alpha)
    command = [
        "--port", str(config["port"]),
        "--tool", "echo",
        "--arguments-json", json.dumps(args),
        "--permit-file", str(permit_path),
    ]
    service = _start_service(policy, "http://127.0.0.1:" + str(config["port"]))
    try:
        assert main(command) == 0
        allowed = json.loads(capsys.readouterr().out)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result"] == args["text"]
        assert alpha not in json.dumps(allowed)
        assert "permit" not in json.dumps(allowed)

        # New MCP relay process and fresh request ID still cannot reuse the
        # consumed signed permit in the persistent SQLite audit ledger.
        assert main(command) == 2
        refused = json.loads(capsys.readouterr().out)
        assert refused["decision"] == "DENY"
        assert refused["error"] == "Governed execution refused"
        assert alpha not in json.dumps(refused)
    finally:
        _stop(service)
