"""Provider-level adversarial tests against a real loopback HTTP provider."""

from __future__ import annotations

import logging

import pytest

from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.execution.scope import ExecutionScope, execution_scope
from shards_kernel.providers.github_issue_label import (
    TOOL_NAME,
    EnvTokenSupplier,
    GitHubIssueLabelConfig,
    GitHubIssueLabelProvider,
    ProviderEffectUnknown,
    ProviderOutcome,
    ProviderValidationError,
    derive_operation_id,
)
from shards_kernel.providers.journal import (
    SUCCEEDED,
    UNKNOWN,
    ProviderEffectJournal,
    ProviderJournalError,
)
from tests.github_issue_label_test_server import GitHubTestProvider, LoopbackTransport


@pytest.fixture
def server():
    test_provider = GitHubTestProvider().start()
    try:
        yield test_provider
    finally:
        test_provider.stop()


def make_provider(
    tmp_path,
    server: GitHubTestProvider,
    *,
    labels: tuple[str, ...] = ("triage",),
    max_issue: int = 100,
    token: str | None = None,
    timeout: float = 10.0,
):
    journal = ProviderEffectJournal(str(tmp_path / "journal.sqlite3"))
    config = GitHubIssueLabelConfig(
        owner="octo",
        repo="demo",
        allowed_labels=frozenset(labels),
        max_issue_number=max_issue,
        timeout_seconds=timeout,
    )
    provider = GitHubIssueLabelProvider(
        config=config,
        journal=journal,
        token_supplier=lambda: token or server.token,
        transport=LoopbackTransport(server.base_url),
    )
    return provider, journal


def operation_id(
    issue: int,
    label: str,
    *,
    request_id: str = "req-1",
    permit_id: str = "p" * 64,
) -> str:
    params = compute_hash_dict({"issue_number": issue, "label": label})
    return derive_operation_id(
        request_id=request_id, permit_id=permit_id, params_sha256=params
    )


def test_add_label_posts_then_verifies_by_readback(tmp_path, server):
    server.add_issue(7)
    provider, journal = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7,
        label="triage",
        operation_id=operation_id(7, "triage"),
        request_id="req-1",
        permit_id="p" * 64,
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert effect.already_present is False
    assert effect.provider_ref == "github:octo/demo#7:triage"
    assert server.post_count == 1
    assert server.get_count >= 1
    assert server.labels[7] == {"triage"}
    assert journal.get(operation_id(7, "triage")).state == SUCCEEDED


def test_existing_label_is_idempotent_and_does_not_post(tmp_path, server):
    server.add_issue(7, {"triage"})
    provider, _ = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7,
        label="triage",
        operation_id=operation_id(7, "triage"),
        request_id="req-1",
        permit_id="p" * 64,
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert effect.already_present is True
    assert server.post_count == 0


@pytest.mark.parametrize("status", [403, 409, 429, 500, 502, 503])
def test_ambiguous_http_error_is_quarantined_without_retry(tmp_path, server, status):
    server.add_issue(7)
    server.post_status = status
    provider, journal = make_provider(tmp_path, server)
    op = operation_id(7, "triage")
    effect = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.UNKNOWN
    assert journal.get(op).state == UNKNOWN
    assert server.post_count == 1
    # Re-entering the same operation must never send a second POST.
    again = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert again.state is ProviderOutcome.UNKNOWN
    assert server.post_count == 1


def test_timeout_after_dispatch_is_unknown_and_not_retried(tmp_path, server):
    server.add_issue(7)
    server.delay_seconds_after_post = 1.5
    provider, journal = make_provider(tmp_path, server, timeout=1.0)
    op = operation_id(7, "triage")
    effect = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.UNKNOWN
    assert journal.get(op).state == UNKNOWN
    assert server.post_count == 1


def test_definitive_rejection_is_not_applied(tmp_path, server):
    server.add_issue(7)
    server.post_status = 422
    provider, journal = make_provider(tmp_path, server)
    op = operation_id(7, "triage")
    effect = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.NOT_APPLIED
    assert journal.get(op).state == "NOT_APPLIED"
    assert server.post_count == 1


def test_missing_issue_is_not_applied_without_post(tmp_path, server):
    provider, journal = make_provider(tmp_path, server)
    op = operation_id(9, "triage")
    effect = provider.add_label(
        issue_number=9, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.NOT_APPLIED
    assert server.post_count == 0


def test_readback_wins_over_ambiguous_http_status(tmp_path, server):
    server.add_issue(7)
    server.apply_then_status = 403
    provider, _ = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7,
        label="triage",
        operation_id=operation_id(7, "triage"),
        request_id="req-1",
        permit_id="p" * 64,
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert effect.already_present is True
    assert server.labels[7] == {"triage"}


@pytest.mark.parametrize(
    "issue,label",
    [
        (0, "triage"),
        (-1, "triage"),
        (101, "triage"),
        (True, "triage"),
        (7, "forbidden"),
        (7, ""),
        (7, " triage"),
    ],
)
def test_bounds_and_label_allowlist_are_enforced(tmp_path, server, issue, label):
    server.add_issue(7)
    provider, _ = make_provider(tmp_path, server, max_issue=100)
    with pytest.raises(ProviderValidationError):
        provider.add_label(
            issue_number=issue,
            label=label,
            operation_id=operation_id(7, "triage"),
            request_id="req-1",
            permit_id="p" * 64,
        )
    assert server.post_count == 0
    assert server.get_count == 0


def test_handler_requires_kernel_scope_and_matching_params(tmp_path, server):
    server.add_issue(7)
    provider, _ = make_provider(tmp_path, server)
    with pytest.raises(ProviderValidationError, match="EXECUTION_SCOPE_REQUIRED"):
        provider.handle_issue_add_label(7, "triage")
    params = compute_hash_dict({"issue_number": 7, "label": "triage"})
    with execution_scope(
        ExecutionScope(
            request_id="req-1",
            actor="agent",
            tool_name=TOOL_NAME,
            permit_id="p" * 64,
            params_sha256=compute_hash_dict({"issue_number": 8, "label": "triage"}),
        )
    ):
        with pytest.raises(ProviderValidationError, match="EXECUTION_SCOPE_PARAMS_MISMATCH"):
            provider.handle_issue_add_label(7, "triage")
    assert server.post_count == 0
    with execution_scope(
        ExecutionScope(
            request_id="req-1",
            actor="agent",
            tool_name=TOOL_NAME,
            permit_id="p" * 64,
            params_sha256=params,
        )
    ):
        result = provider.handle_issue_add_label(7, "triage")
    assert result["state"] == "SUCCEEDED"
    assert server.post_count == 1


def test_unknown_and_not_applied_raise_sanitized_errors(tmp_path, server):
    server.add_issue(7)
    server.post_status = 500
    provider, _ = make_provider(tmp_path, server)
    with pytest.raises(ProviderEffectUnknown) as unknown:
        with execution_scope(
            ExecutionScope(
                request_id="req-1",
                actor="agent",
                tool_name=TOOL_NAME,
                permit_id="p" * 64,
                params_sha256=compute_hash_dict(
                    {"issue_number": 7, "label": "triage"}
                ),
            )
        ):
            provider.handle_issue_add_label(7, "triage")
    assert "PROVIDER_EFFECT_UNKNOWN" in str(unknown.value)

    server.post_status = 422
    provider2, _ = make_provider(tmp_path, server)
    op2 = operation_id(7, "triage", request_id="req-2")
    effect = provider2.add_label(
        issue_number=7, label="triage", operation_id=op2, request_id="req-2", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.NOT_APPLIED


def test_token_never_appears_in_outcome_error_or_logs(tmp_path, server, caplog):
    token = "ghp_UNIQUE_SECRET_TOKEN_0123456789"
    server.add_issue(7)
    provider, _ = make_provider(tmp_path, server, token=token)
    with caplog.at_level(logging.DEBUG):
        effect = provider.add_label(
            issue_number=7,
            label="triage",
            operation_id=operation_id(7, "triage"),
            request_id="req-1",
            permit_id="p" * 64,
        )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert token not in repr(effect.to_mapping())
    assert token not in caplog.text
    assert server.token_seen[-1] == f"Bearer {token}"

    server.add_issue(8)
    server.post_status = 500
    second = tmp_path / "second"
    second.mkdir()
    provider2, _ = make_provider(second, server, token=token)
    effect2 = provider2.add_label(
        issue_number=8,
        label="triage",
        operation_id=operation_id(8, "triage", request_id="req-2"),
        request_id="req-2",
        permit_id="p" * 64,
    )
    assert effect2.state is ProviderOutcome.UNKNOWN
    assert token not in repr(effect2.to_mapping())
    assert token not in caplog.text


def test_journal_restart_preserves_success_without_second_post(tmp_path, server):
    server.add_issue(7)
    provider, journal = make_provider(tmp_path, server)
    op = operation_id(7, "triage")
    assert provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    ).state is ProviderOutcome.SUCCEEDED
    journal.close()

    provider2, journal2 = make_provider(tmp_path, server)
    effect = provider2.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert server.post_count == 1
    assert journal2.get(op).state == SUCCEEDED


def test_crash_after_dispatch_reconciles_present_without_post(tmp_path, server):
    server.add_issue(7, {"triage"})
    journal = ProviderEffectJournal(str(tmp_path / "journal.sqlite3"))
    op = operation_id(7, "triage")
    params = compute_hash_dict({"issue_number": 7, "label": "triage"})
    journal.reserve(
        operation_id=op,
        provider="github",
        resource="octo/demo",
        action="add_label",
        params_sha256=params,
        request_id="req-1",
        permit_id="p" * 64,
    )
    journal.mark_dispatched(op)
    journal.close()

    provider, journal2 = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.SUCCEEDED
    assert effect.reconciled is True
    assert server.post_count == 0
    assert journal2.get(op).state == SUCCEEDED


def test_crash_after_dispatch_absent_stays_unknown_without_post(tmp_path, server):
    server.add_issue(7)
    journal = ProviderEffectJournal(str(tmp_path / "journal.sqlite3"))
    op = operation_id(7, "triage")
    params = compute_hash_dict({"issue_number": 7, "label": "triage"})
    journal.reserve(
        operation_id=op,
        provider="github",
        resource="octo/demo",
        action="add_label",
        params_sha256=params,
        request_id="req-1",
        permit_id="p" * 64,
    )
    journal.mark_dispatched(op)
    journal.close()

    provider, journal2 = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7, label="triage", operation_id=op, request_id="req-1", permit_id="p" * 64
    )
    assert effect.state is ProviderOutcome.UNKNOWN
    assert server.post_count == 0
    assert journal2.get(op).state == UNKNOWN


def test_journal_rejects_operation_id_reuse_with_different_params(tmp_path, server):
    journal = ProviderEffectJournal(str(tmp_path / "journal.sqlite3"))
    op = operation_id(7, "triage")
    journal.reserve(
        operation_id=op,
        provider="github",
        resource="octo/demo",
        action="add_label",
        params_sha256=compute_hash_dict({"issue_number": 7, "label": "triage"}),
        request_id="req-1",
        permit_id="p" * 64,
    )
    with pytest.raises(ProviderJournalError, match="JOURNAL_OPERATION_CONFLICT"):
        journal.reserve(
            operation_id=op,
            provider="github",
            resource="octo/demo",
            action="add_label",
            params_sha256=compute_hash_dict({"issue_number": 8, "label": "triage"}),
            request_id="req-1",
            permit_id="p" * 64,
        )


def test_journal_unavailable_fails_closed_before_any_post(tmp_path, server):
    server.add_issue(7)
    provider, journal = make_provider(tmp_path, server)
    journal.close()
    journal.path.unlink()
    journal.path.mkdir()
    with pytest.raises(ProviderEffectUnknown, match="PROVIDER_JOURNAL_UNAVAILABLE"):
        provider.add_label(
            issue_number=7,
            label="triage",
            operation_id=operation_id(7, "triage"),
            request_id="req-1",
            permit_id="p" * 64,
        )
    assert server.post_count == 0


def test_malformed_readback_is_not_success(tmp_path, server):
    server.add_issue(7)
    server.malformed_readback = True
    provider, _ = make_provider(tmp_path, server)
    effect = provider.add_label(
        issue_number=7,
        label="triage",
        operation_id=operation_id(7, "triage"),
        request_id="req-1",
        permit_id="p" * 64,
    )
    assert effect.state is ProviderOutcome.NOT_APPLIED
    assert server.post_count == 0


def test_env_token_supplier_never_returns_invalid_values(monkeypatch):
    supplier = EnvTokenSupplier("SHARDS_KERNEL_TEST_GITHUB_TOKEN")
    monkeypatch.delenv("SHARDS_KERNEL_TEST_GITHUB_TOKEN", raising=False)
    with pytest.raises(ProviderValidationError, match="GITHUB_TOKEN_UNAVAILABLE"):
        supplier()
    monkeypatch.setenv("SHARDS_KERNEL_TEST_GITHUB_TOKEN", "short")
    with pytest.raises(ProviderValidationError, match="GITHUB_TOKEN_INVALID"):
        supplier()
    monkeypatch.setenv("SHARDS_KERNEL_TEST_GITHUB_TOKEN", "ghp_" + "a" * 40)
    assert supplier().startswith("ghp_")


def test_config_rejects_unsafe_scope_and_nonproduction_base():
    with pytest.raises(ProviderValidationError):
        GitHubIssueLabelConfig(owner="../x", repo="demo", allowed_labels=frozenset({"triage"}))
    with pytest.raises(ProviderValidationError):
        GitHubIssueLabelConfig(owner="octo", repo="demo", allowed_labels=frozenset())
    with pytest.raises(ProviderValidationError):
        GitHubIssueLabelConfig(
            owner="octo", repo="demo", allowed_labels=frozenset({"triage"}),
            api_base="http://127.0.0.1:1234",
        )
    with pytest.raises(ProviderValidationError):
        GitHubIssueLabelConfig(
            owner="octo", repo="demo", allowed_labels=frozenset({"triage"}),
            timeout_seconds=0.1,
        )
