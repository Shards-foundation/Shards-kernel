"""Allowlisted GitHub issue label provider.

The only external effect this adapter can perform is adding one label, from a
fixed allowlist, to an already existing issue in one fixed owner/repository.
It never deletes labels, merges pull requests, accepts a URL, shell command or
credential from a request, or exposes the operator's GitHub token.

Every invocation is bound to a kernel-authored :class:`ExecutionScope` and a
durable intent/effect journal. An ambiguous response is quarantined as
``UNKNOWN`` and is never retried automatically; only authoritative read-back
can resolve it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Protocol

from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.execution.scope import current_execution_scope
from shards_kernel.providers.journal import (
    DISPATCHED,
    INTENT,
    NOT_APPLIED,
    SUCCEEDED,
    UNKNOWN,
    ProviderEffectJournal,
    ProviderEffectRecord,
    ProviderJournalError,
)

GITHUB_API_BASE = "https://api.github.com"
TOOL_NAME = "github.issue.add_label"
_PROVIDER_NAME = "github"
_MAX_BODY_BYTES = 1024 * 1024
_MAX_PAGES = 5
_DEFAULT_TIMEOUT_SECONDS = 10.0
_MAX_LABEL_LENGTH = 100
_MAX_PROVIDER_REFERENCE = 200
_REFERENCE_DIGEST_PREFIX = "github:sha256:"
_MAX_ISSUE_NUMBER = 10_000_000
_TOKEN_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")


class ProviderOutcome(str, Enum):
    """Durable effect classification returned to the kernel."""

    SUCCEEDED = SUCCEEDED
    NOT_APPLIED = NOT_APPLIED
    UNKNOWN = UNKNOWN


class ProviderError(RuntimeError):
    """Base class for a sanitized provider failure."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        message = code if not detail else f"{code}: {detail}"
        super().__init__(message)


class ProviderValidationError(ProviderError):
    """The request or configuration is outside the supported envelope."""


class ProviderNotApplied(ProviderError):
    """The provider definitively did not apply the effect."""


class ProviderEffectUnknown(ProviderError):
    """The provider outcome is ambiguous and must be quarantined."""


class TransportFailure(ProviderError):
    """The HTTP transport failed before a definitive response was available."""


@dataclass(frozen=True)
class HttpResponse:
    """Minimal bounded HTTP response. No request headers are retained."""

    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)


class HttpTransport(Protocol):
    """Injectable HTTP transport. The production default is urllib."""

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout: float,
    ) -> HttpResponse:
        raise NotImplementedError


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class UrllibHttpTransport:
    """Standard-library HTTPS transport with redirects disabled."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout: float,
    ) -> HttpResponse:
        request = urllib.request.Request(
            url=url, data=body, headers=dict(headers), method=method
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:  # nosec B310: fixed operator URL
                return HttpResponse(
                    status=int(response.status),
                    body=response.read(_MAX_BODY_BYTES),
                    headers=dict(response.headers),
                )
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read(_MAX_BODY_BYTES)
            except Exception:
                payload = b""
            return HttpResponse(
                status=int(exc.code), body=payload, headers=dict(exc.headers or {})
            )
        except Exception as exc:  # Never echo URL, headers or credential values.
            raise TransportFailure("TRANSPORT_FAILURE", type(exc).__name__) from None


def _bounded_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or not value.isascii()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ProviderValidationError("INVALID_" + label.upper())
    return value


def _validated_label(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_LABEL_LENGTH
        or value != value.strip()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ProviderValidationError("INVALID_LABEL")
    return value


def _validated_issue_number(value: Any, maximum: int) -> int:
    # bool is a subclass of int; a JSON ``true`` must never become issue 1.
    if type(value) is not int or value < 1 or value > maximum:
        raise ProviderValidationError("INVALID_ISSUE_NUMBER")
    return value


def _provider_reference(owner: str, repo: str, issue: int, label: str) -> str:
    """Return a bounded, ASCII-safe reference for the durable journal.

    The readable ``github:owner/repo#issue:label`` form is kept when it fits
    the journal's reference bound. A Unicode or over-long value is replaced by
    a SHA-256 digest over the exact owner/repo/issue/label tuple. The digest is
    deterministic and collision-resistant, so it never silently truncates or
    aliases two different effects. The journal's ``params_sha256`` remains the
    authoritative parameter binding; this reference is evidence only.
    """
    plain = f"github:{owner}/{repo}#{issue}:{label}"
    if (
        len(plain) <= _MAX_PROVIDER_REFERENCE
        and plain.isascii()
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in plain)
    ):
        return plain
    digest = compute_hash_dict(
        {
            "domain": "SHARDS-PROVIDER-REFERENCE-V1",
            "provider": _PROVIDER_NAME,
            "owner": owner,
            "repo": repo,
            "issue": issue,
            "label": label,
        }
    )
    return _REFERENCE_DIGEST_PREFIX + digest


def _validated_token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not 20 <= len(value) <= 512
        or any(ch.isspace() for ch in value)
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ProviderValidationError("GITHUB_TOKEN_INVALID")
    return value


@dataclass(frozen=True)
class EnvTokenSupplier:
    """Resolve the operator-held GitHub credential from one named env var."""

    env_name: str

    def __post_init__(self) -> None:
        if not isinstance(self.env_name, str) or not _TOKEN_ENV_RE.match(self.env_name):
            raise ProviderValidationError("GITHUB_TOKEN_ENV_INVALID")

    def __call__(self) -> str:
        value = os.environ.get(self.env_name)
        if value is None:
            raise ProviderValidationError("GITHUB_TOKEN_UNAVAILABLE")
        return _validated_token(value)


@dataclass(frozen=True)
class GitHubIssueLabelConfig:
    """Operator-pinned provider scope. Contains no credential value."""

    owner: str
    repo: str
    allowed_labels: frozenset[str]
    max_issue_number: int = 100_000
    api_base: str = GITHUB_API_BASE
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    token_env: str = "SHARDS_KERNEL_GITHUB_TOKEN"

    def __post_init__(self) -> None:
        for value, label in ((self.owner, "owner"), (self.repo, "repo")):
            if not isinstance(value, str) or not _OWNER_RE.match(value) or value in {".", ".."}:
                raise ProviderValidationError("INVALID_" + label.upper())
        if len(f"{self.owner}/{self.repo}") > _MAX_PROVIDER_REFERENCE:
            raise ProviderValidationError("RESOURCE_TOO_LONG")
        if not isinstance(self.allowed_labels, frozenset) or not self.allowed_labels:
            raise ProviderValidationError("LABEL_ALLOWLIST_REQUIRED")
        if len(self.allowed_labels) > 32:
            raise ProviderValidationError("LABEL_ALLOWLIST_TOO_LARGE")
        for label in self.allowed_labels:
            _validated_label(label)
        if (
            type(self.max_issue_number) is not int
            or not 1 <= self.max_issue_number <= _MAX_ISSUE_NUMBER
        ):
            raise ProviderValidationError("INVALID_MAX_ISSUE_NUMBER")
        if self.api_base != GITHUB_API_BASE:
            raise ProviderValidationError("PRODUCTION_API_BASE_REQUIRED")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 1.0 <= float(self.timeout_seconds) <= 60.0
        ):
            raise ProviderValidationError("INVALID_TIMEOUT")
        if not isinstance(self.token_env, str) or not _TOKEN_ENV_RE.match(self.token_env):
            raise ProviderValidationError("GITHUB_TOKEN_ENV_INVALID")

    @property
    def resource(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class ProviderEffect:
    """Outcome of one provider operation, safe to return to the kernel."""

    operation_id: str
    state: ProviderOutcome
    issue_number: int
    label: str
    already_present: bool
    provider_ref: str
    detail: str
    reconciled: bool = False

    def to_mapping(self) -> dict[str, Any]:
        return {
            "provider": _PROVIDER_NAME,
            "action": "add_label",
            "operation_id": self.operation_id,
            "state": self.state.value,
            "issue_number": self.issue_number,
            "label": self.label,
            "already_present": self.already_present,
            "provider_ref": self.provider_ref,
            "detail": self.detail,
            "reconciled": self.reconciled,
        }


def derive_operation_id(
    *, request_id: str, permit_id: str, params_sha256: str
) -> str:
    """Bind one journal operation to one kernel request and signed permit."""
    for value, label in (
        (request_id, "request_id"),
        (permit_id, "permit_id"),
        (params_sha256, "params_sha256"),
    ):
        if not isinstance(value, str) or len(value) > 500:
            raise ProviderValidationError("INVALID_" + label.upper())
    payload = "\x00".join(
        (
            "SHARDS-PROVIDER-OPERATION-V1",
            _PROVIDER_NAME,
            TOOL_NAME,
            request_id,
            permit_id,
            params_sha256,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _ReadbackUnavailable(Exception):
    pass


class _ReadbackIssueMissing(Exception):
    pass


class GitHubIssueLabelProvider:
    """Perform only ``add label`` on a pre-existing issue in one repository."""

    def __init__(
        self,
        *,
        config: GitHubIssueLabelConfig,
        journal: ProviderEffectJournal,
        token_supplier: Any,
        transport: Optional[HttpTransport] = None,
    ) -> None:
        if not isinstance(config, GitHubIssueLabelConfig):
            raise ProviderValidationError("INVALID_PROVIDER_CONFIG")
        if not isinstance(journal, ProviderEffectJournal):
            raise ProviderValidationError("INVALID_PROVIDER_JOURNAL")
        if not callable(token_supplier):
            raise ProviderValidationError("INVALID_TOKEN_SUPPLIER")
        self._config = config
        self._journal = journal
        self._token_supplier = token_supplier
        self._transport = transport or UrllibHttpTransport()

    @property
    def config(self) -> GitHubIssueLabelConfig:
        return self._config

    @property
    def tool_name(self) -> str:
        return TOOL_NAME

    def handle_issue_add_label(self, issue_number: int, label: str) -> dict[str, Any]:
        """Kernel-registered handler. Requires a kernel-authored execution scope.

        This is the only supported entrypoint for a governed request. A direct
        call without a scope fails closed before any provider request is made.
        """
        scope = current_execution_scope()
        if scope is None:
            raise ProviderValidationError("EXECUTION_SCOPE_REQUIRED")
        if scope.tool_name != TOOL_NAME:
            raise ProviderValidationError("EXECUTION_SCOPE_MISMATCH")
        if not scope.permit_id:
            raise ProviderValidationError("EXECUTION_SCOPE_PERMIT_REQUIRED")
        validated_issue = _validated_issue_number(
            issue_number, self._config.max_issue_number
        )
        validated_label = _validated_label(label)
        expected_params = compute_hash_dict(
            {"issue_number": validated_issue, "label": validated_label}
        )
        if scope.params_sha256 != expected_params:
            raise ProviderValidationError("EXECUTION_SCOPE_PARAMS_MISMATCH")
        operation_id = derive_operation_id(
            request_id=scope.request_id,
            permit_id=scope.permit_id,
            params_sha256=scope.params_sha256,
        )
        effect = self.add_label(
            issue_number=validated_issue,
            label=validated_label,
            operation_id=operation_id,
            request_id=scope.request_id,
            permit_id=scope.permit_id,
        )
        if effect.state is ProviderOutcome.SUCCEEDED:
            return effect.to_mapping()
        if effect.state is ProviderOutcome.UNKNOWN:
            raise ProviderEffectUnknown("PROVIDER_EFFECT_UNKNOWN", effect.detail)
        raise ProviderNotApplied("PROVIDER_NOT_APPLIED", effect.detail)

    def check_label_present(self, issue_number: int, label: str) -> bool:
        """Read-only authoritative check. Never writes, journals or retries."""
        issue = _validated_issue_number(issue_number, self._config.max_issue_number)
        validated_label = _validated_label(label)
        if validated_label not in self._config.allowed_labels:
            raise ProviderValidationError("LABEL_NOT_ALLOWED")
        token = _validated_token(self._token_supplier())
        try:
            return self._label_present(issue, validated_label, token)
        except (_ReadbackIssueMissing, _ReadbackUnavailable):
            raise ProviderEffectUnknown("READBACK_UNAVAILABLE") from None

    def add_label(
        self,
        *,
        issue_number: int,
        label: str,
        operation_id: str,
        request_id: str,
        permit_id: str,
    ) -> ProviderEffect:
        """Perform or reconcile one idempotent label addition."""
        issue = _validated_issue_number(issue_number, self._config.max_issue_number)
        label = _validated_label(label)
        if label not in self._config.allowed_labels:
            raise ProviderValidationError("LABEL_NOT_ALLOWED")
        _bounded_identifier(operation_id, "operation_id")
        _bounded_identifier(request_id, "request_id")
        if not isinstance(permit_id, str) or not permit_id:
            raise ProviderValidationError("PERMIT_ID_REQUIRED")

        params_sha256 = compute_hash_dict(
            {"issue_number": issue, "label": label}
        )
        try:
            record = self._journal.reserve(
                operation_id=operation_id,
                provider=_PROVIDER_NAME,
                resource=self._config.resource,
                action="add_label",
                params_sha256=params_sha256,
                request_id=request_id,
                permit_id=permit_id,
            )
        except ProviderJournalError:
            raise ProviderEffectUnknown("PROVIDER_JOURNAL_UNAVAILABLE") from None

        if record.state == SUCCEEDED or record.state == NOT_APPLIED:
            self._assert_record_binding(record, issue, label)
            return self._effect_from_record(record, issue, label, reconciled=False)
        if record.state == DISPATCHED or record.state == UNKNOWN:
            return self._reconcile(record, issue, label)
        if record.state != INTENT:
            raise ProviderEffectUnknown("PROVIDER_JOURNAL_STATE_INVALID")

        try:
            token = _validated_token(self._token_supplier())
        except ProviderError:
            return self._record_and_return(
                operation_id, issue, label, NOT_APPLIED, "TOKEN_UNAVAILABLE"
            )
        except Exception:
            return self._record_and_return(
                operation_id, issue, label, NOT_APPLIED, "TOKEN_UNAVAILABLE"
            )

        # Preflight read-back: no POST is sent when the label is already there.
        try:
            present = self._label_present(issue, label, token)
        except _ReadbackIssueMissing:
            return self._record_and_return(
                operation_id, issue, label, NOT_APPLIED, "ISSUE_NOT_FOUND"
            )
        except _ReadbackUnavailable:
            # No provider request was sent, so no effect was applied by us.
            return self._record_and_return(
                operation_id, issue, label, NOT_APPLIED, "PREFLIGHT_UNAVAILABLE"
            )
        if present:
            return self._record_and_return(
                operation_id, issue, label, SUCCEEDED, "ALREADY_PRESENT", already_present=True
            )

        try:
            self._journal.mark_dispatched(operation_id)
        except ProviderJournalError:
            raise ProviderEffectUnknown("PROVIDER_JOURNAL_UNAVAILABLE") from None

        classification = self._post_label(issue, label, token)
        return self._finish_after_dispatch(
            operation_id, issue, label, token, classification
        )

    def _assert_record_binding(
        self, record: ProviderEffectRecord, issue: int, label: str
    ) -> None:
        """Refuse a terminal record that belongs to different parameters."""
        expected_params = compute_hash_dict(
            {"issue_number": issue, "label": label}
        )
        if (
            record.provider != _PROVIDER_NAME
            or record.resource != self._config.resource
            or record.action != "add_label"
            or record.params_sha256 != expected_params
        ):
            raise ProviderEffectUnknown("PROVIDER_JOURNAL_BINDING_MISMATCH")

    def _reconcile(
        self, record: ProviderEffectRecord, issue: int, label: str
    ) -> ProviderEffect:
        """Read back only; never re-send an operation that may have applied."""
        self._assert_record_binding(record, issue, label)
        try:
            token = _validated_token(self._token_supplier())
        except Exception:
            return self._effect_from_record(record, issue, label, reconciled=True)
        try:
            present = self._label_present(issue, label, token)
        except (_ReadbackUnavailable, _ReadbackIssueMissing):
            return self._effect_from_record(record, issue, label, reconciled=True)
        if present:
            return self._record_and_return(
                record.operation_id, issue, label, SUCCEEDED, "RECONCILED_READBACK",
                already_present=True, reconciled=True,
            )
        # Missing read-back is not proof of absence for an already dispatched
        # or previously ambiguous operation.
        return self._record_and_return(
            record.operation_id, issue, label, UNKNOWN, "AMBIGUOUS_NO_READBACK_PROOF",
            reconciled=True,
        )

    def _post_label(self, issue: int, label: str, token: str) -> str:
        """Return ``ok``, ``definitive_reject`` or ``ambiguous``. No retry."""
        url = (
            f"{self._config.api_base}/repos/{self._config.owner}/"
            f"{self._config.repo}/issues/{issue}/labels"
        )
        body = json.dumps({"labels": [label]}, separators=(",", ":")).encode("utf-8")
        try:
            response = self._transport.request(
                "POST", url, self._headers(token), body, float(self._config.timeout_seconds)
            )
        except Exception:
            return "ambiguous"
        if response.status in (200, 201):
            return "ok"
        if response.status in (404, 410, 422):
            return "definitive_reject"
        return "ambiguous"

    def _finish_after_dispatch(
        self, operation_id: str, issue: int, label: str, token: str, classification: str
    ) -> ProviderEffect:
        try:
            present = self._label_present(issue, label, token)
        except _ReadbackIssueMissing:
            # A missing issue after a dispatch cannot prove the label was never
            # added; quarantine unless the POST was a definitive rejection.
            if classification == "definitive_reject":
                return self._record_and_return(
                    operation_id, issue, label, NOT_APPLIED, "ISSUE_NOT_FOUND"
                )
            return self._record_and_return(
                operation_id, issue, label, UNKNOWN, "ISSUE_MISSING_AFTER_DISPATCH"
            )
        except _ReadbackUnavailable:
            if classification == "definitive_reject":
                return self._record_and_return(
                    operation_id, issue, label, UNKNOWN, "READBACK_UNAVAILABLE_AFTER_REJECT"
                )
            return self._record_and_return(
                operation_id, issue, label, UNKNOWN, "READBACK_UNAVAILABLE_AFTER_DISPATCH"
            )
        if present:
            return self._record_and_return(
                operation_id, issue, label, SUCCEEDED, "VERIFIED_READBACK",
                already_present=classification != "ok",
            )
        if classification == "definitive_reject":
            return self._record_and_return(
                operation_id, issue, label, NOT_APPLIED, "PROVIDER_REJECTED"
            )
        # Accepted-but-not-visible or ambiguous: never claim success.
        return self._record_and_return(
            operation_id, issue, label, UNKNOWN, "AMBIGUOUS_NO_READBACK_PROOF"
        )

    def _label_present(self, issue: int, label: str, token: str) -> bool:
        """Authoritative read-back. Missing/unreadable evidence is never success."""
        for page in range(1, _MAX_PAGES + 1):
            url = (
                f"{self._config.api_base}/repos/{self._config.owner}/{self._config.repo}"
                f"/issues/{issue}/labels?per_page=100&page={page}"
            )
            try:
                response = self._transport.request(
                    "GET", url, self._headers(token), None, float(self._config.timeout_seconds)
                )
            except Exception:
                raise _ReadbackUnavailable() from None
            if response.status in (404, 410):
                raise _ReadbackIssueMissing()
            if response.status != 200:
                raise _ReadbackUnavailable()
            names = self._parse_label_names(response.body)
            if names is None:
                raise _ReadbackUnavailable()
            if label in names:
                return True
            if len(names) < 100:
                return False
        raise _ReadbackUnavailable()

    @staticmethod
    def _parse_label_names(body: bytes) -> Optional[list[str]]:
        if not isinstance(body, (bytes, bytearray)) or len(body) > _MAX_BODY_BYTES:
            return None
        try:
            decoded = json.loads(bytes(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, list):
            return None
        names: list[str] = []
        for item in decoded:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                return None
            names.append(item["name"])
        return names

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "shards-kernel-github-label-provider",
            "Content-Type": "application/json",
        }

    def _record_and_return(
        self,
        operation_id: str,
        issue: int,
        label: str,
        state: str,
        detail: str,
        *,
        already_present: bool = False,
        reconciled: bool = False,
    ) -> ProviderEffect:
        provider_ref = _provider_reference(
            self._config.owner, self._config.repo, issue, label
        )
        try:
            record = self._journal.record_outcome(
                operation_id,
                state,
                provider_ref=provider_ref,
                detail=detail,
                expected_provider=_PROVIDER_NAME,
                expected_resource=self._config.resource,
                expected_action="add_label",
                expected_params_sha256=compute_hash_dict(
                    {"issue_number": issue, "label": label}
                ),
            )
        except ProviderJournalError:
            # The journal is the durable authority. If it cannot record the
            # outcome, do not report success to the kernel.
            raise ProviderEffectUnknown("PROVIDER_JOURNAL_UNAVAILABLE") from None
        return self._effect_from_record(
            record, issue, label, already_present=already_present, reconciled=reconciled
        )

    @staticmethod
    def _effect_from_record(
        record: ProviderEffectRecord,
        issue: int,
        label: str,
        *,
        already_present: bool = False,
        reconciled: bool = False,
    ) -> ProviderEffect:
        try:
            state = ProviderOutcome(record.state)
        except ValueError:
            state = ProviderOutcome.UNKNOWN
        return ProviderEffect(
            operation_id=record.operation_id,
            state=state,
            issue_number=issue,
            label=label,
            already_present=already_present,
            provider_ref=record.provider_ref,
            detail=record.detail,
            reconciled=reconciled,
        )
