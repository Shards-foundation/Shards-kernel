"""The deploy template must parse and the unit must stay hardened."""

from __future__ import annotations

import json
from pathlib import Path

from shards_kernel.cli.service import parse_operator_config
from shards_kernel.providers.github_issue_label import TOOL_NAME

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "github-operator.config.example.json"
UNIT = ROOT / "deploy" / "systemd" / "shards-kernel-github-operator.service"
ENV = ROOT / "deploy" / "systemd" / "github-operator.env.example"


def test_config_template_is_valid_v3_without_credentials(tmp_path):
    raw = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    raw["audit_db"] = str(tmp_path / "audit.sqlite3")
    raw["provider"]["journal_db"] = str(tmp_path / "journal.sqlite3")
    config = parse_operator_config(raw)
    assert config.version == 3
    assert config.provider is not None
    assert config.gateway is not None
    assert TOOL_NAME in config.tools
    assert config.provider.allowed_labels == ("shards-agent",)
    assert config.provider.token_env == "SHARDS_KERNEL_GITHUB_TOKEN"
    assert config.gateway.token_env == "SHARDS_KERNEL_GATEWAY_TOKEN"
    serialized = TEMPLATE.read_text(encoding="utf-8")
    assert "ghp_" not in serialized
    assert "Bearer " not in serialized
    assert "SHARDS_KERNEL_GITHUB_TOKEN=" not in serialized


def test_systemd_unit_is_loopback_only_and_hardened():
    unit = UNIT.read_text(encoding="utf-8")
    for required in (
        "User=shards-kernel",
        "Group=shards-kernel",
        "EnvironmentFile=/etc/shards-kernel/github-operator.env",
        "ExecStart=/opt/shards-kernel/.venv/bin/python -m shards_kernel serve "
        "--config /etc/shards-kernel/github-operator.signed.json",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "PrivateUsers=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "RestrictNamespaces=yes",
        "MemoryDenyWriteExecute=yes",
        "SystemCallFilter=@system-service",
        "CapabilityBoundingSet=",
        "ReadWritePaths=/var/lib/shards-kernel/github-operator",
        "StateDirectory=shards-kernel/github-operator",
        "UMask=0077",
    ):
        assert required in unit
    assert "0.0.0.0" not in unit
    assert "::" not in unit
    assert "Restart=always" not in unit


def test_env_template_contains_names_only():
    lines = ENV.read_text(encoding="utf-8").splitlines()
    assignments = [line for line in lines if line and not line.lstrip().startswith("#")]
    assert assignments
    for line in assignments:
        name, separator, value = line.partition("=")
        assert separator == "="
        assert name.startswith("SHARDS_KERNEL_")
        assert value == ""
    assert "SHARDS_KERNEL_GITHUB_TOKEN=" in assignments
    assert "SHARDS_KERNEL_GATEWAY_TOKEN=" in assignments
