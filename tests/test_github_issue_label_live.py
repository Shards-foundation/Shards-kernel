"""Gated LIVE GitHub acceptance. Skipped unless the operator supplies a repo.

Required environment (never committed, never printed):
  SHARDS_KERNEL_LIVE_GITHUB_TOKEN   fine-grained token with issues:read
  SHARDS_KERNEL_LIVE_GITHUB_REPO    owner/repo of a disposable test repository
  SHARDS_KERNEL_LIVE_GITHUB_ISSUE   existing issue number
  SHARDS_KERNEL_LIVE_GITHUB_LABEL   label already configured on that repository

Set SHARDS_KERNEL_LIVE_GITHUB_WRITE=1 only to exercise the add-label write and
its authoritative read-back against that disposable repository.
"""

from __future__ import annotations

import os

import pytest

from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.providers.github_issue_label import (
    EnvTokenSupplier,
    GitHubIssueLabelConfig,
    GitHubIssueLabelProvider,
    ProviderOutcome,
    derive_operation_id,
)
from shards_kernel.providers.journal import ProviderEffectJournal

_REQUIRED = (
    "SHARDS_KERNEL_LIVE_GITHUB_TOKEN",
    "SHARDS_KERNEL_LIVE_GITHUB_REPO",
    "SHARDS_KERNEL_LIVE_GITHUB_ISSUE",
    "SHARDS_KERNEL_LIVE_GITHUB_LABEL",
)
_missing = [name for name in _REQUIRED if not os.environ.get(name)]
pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason="LIVE GitHub acceptance requires operator-controlled test repository secrets",
)


def test_live_github_readback_and_optional_add(tmp_path):
    repo = os.environ["SHARDS_KERNEL_LIVE_GITHUB_REPO"]
    owner, separator, name = repo.partition("/")
    assert separator == "/" and owner and name
    issue = int(os.environ["SHARDS_KERNEL_LIVE_GITHUB_ISSUE"])
    label = os.environ["SHARDS_KERNEL_LIVE_GITHUB_LABEL"]
    journal = ProviderEffectJournal(str(tmp_path / "live-journal.sqlite3"))
    provider = GitHubIssueLabelProvider(
        config=GitHubIssueLabelConfig(
            owner=owner,
            repo=name,
            allowed_labels=frozenset({label}),
            max_issue_number=max(issue, 1),
            token_env="SHARDS_KERNEL_LIVE_GITHUB_TOKEN",
        ),
        journal=journal,
        token_supplier=EnvTokenSupplier("SHARDS_KERNEL_LIVE_GITHUB_TOKEN"),
    )
    assert isinstance(provider.check_label_present(issue, label), bool)

    if os.environ.get("SHARDS_KERNEL_LIVE_GITHUB_WRITE") != "1":
        return
    params_sha = compute_hash_dict({"issue_number": issue, "label": label})
    operation_id = derive_operation_id(
        request_id="live-readback-" + str(issue),
        permit_id="live-operator-acceptance",
        params_sha256=params_sha,
    )
    effect = provider.add_label(
        issue_number=issue,
        label=label,
        operation_id=operation_id,
        request_id="live-readback-" + str(issue),
        permit_id="live-operator-acceptance",
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert provider.check_label_present(issue, label) is True
