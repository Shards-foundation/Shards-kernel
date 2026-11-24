"""Trusted, narrowly scoped external provider adapters.

Adapters in this package perform one allowlisted, reversible, non-financial
effect. They are not a general remote tool runtime and never accept a URL,
tool name, shell command or credential from an agent request.
"""

from shards_kernel.providers.github_issue_label import (
    GITHUB_API_BASE,
    EnvTokenSupplier,
    GitHubIssueLabelConfig,
    GitHubIssueLabelProvider,
    HttpResponse,
    HttpTransport,
    ProviderEffect,
    ProviderEffectUnknown,
    ProviderError,
    ProviderNotApplied,
    ProviderOutcome,
    ProviderValidationError,
    TransportFailure,
    UrllibHttpTransport,
    derive_operation_id,
)
from shards_kernel.providers.journal import (
    ProviderEffectJournal,
    ProviderEffectRecord,
    ProviderJournalError,
)

__all__ = [
    "GITHUB_API_BASE",
    "EnvTokenSupplier",
    "GitHubIssueLabelConfig",
    "GitHubIssueLabelProvider",
    "HttpTransport",
    "HttpResponse",
    "ProviderEffect",
    "ProviderEffectUnknown",
    "ProviderError",
    "ProviderNotApplied",
    "ProviderOutcome",
    "ProviderValidationError",
    "TransportFailure",
    "UrllibHttpTransport",
    "derive_operation_id",
    "ProviderEffectJournal",
    "ProviderEffectRecord",
    "ProviderJournalError",
]
