"""Base kernel protocol and abstract implementation.

All kernel variants must implement the Kernel protocol. The BaseKernel
provides common functionality that variants can extend.
"""

import copy
from abc import ABC, abstractmethod
from threading import Lock
from typing import Any, Callable, Optional

from shards_kernel.common.codec import equal_json_values

from shards_kernel.common.types import (
    Decision,
    DecisionEnvelope,
    EvidenceBundle,
    KernelConfig,
    KernelReceipt,
    KernelRequest,
    KernelState,
    ReceiptStatus,
    ToolCall,
)
from shards_kernel.common.errors import (
    AuditError,
    BootError,
    StateError,
)
from shards_kernel.common.validate import validate_request, check_ambiguity
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.jurisdiction.rules import evaluate_policy
from shards_kernel.state.machine import StateMachine
from shards_kernel.execution.tools import create_default_registry
from shards_kernel.execution.dispatcher import Dispatcher, resolve_bound_params, resolve_effective_params
from shards_kernel.core.runtime import (
    ExecutionContext,
    KernelRuntime,
    RuntimeEvent,
    RuntimeExecutionResult,
)
from shards_kernel.permits import (
    NonceRegistry,
    PermitToken,
    PublicVerificationKey,
    _params_satisfy_permit,
    verify_permit,
)


class Kernel(ABC):
    """Protocol defining the kernel API surface.

    All kernel variants must implement these methods.
    """

    @abstractmethod
    def boot(self, config: KernelConfig) -> None:
        """Boot the kernel with configuration.

        Args:
            config: Kernel configuration.

        Raises:
            BootError: If boot fails.
        """
        ...

    @abstractmethod
    def get_state(self) -> KernelState:
        """Get the current kernel state.

        Returns:
            Current state.
        """
        ...

    @abstractmethod
    def submit(
        self, request: KernelRequest, permit_token: Optional[PermitToken] = None
    ) -> KernelReceipt:
        """Submit a request for processing.

        Args:
            request: Request to process.
            permit_token: Permit token authorizing this request
                (required for execution in most variants).

        Returns:
            Receipt with processing result.
        """
        ...

    @abstractmethod
    def step(self) -> Optional[KernelReceipt]:
        """Advance the kernel by one step.

        Returns:
            Receipt if a step was taken, None if idle.
        """
        ...

    @abstractmethod
    def halt(self, reason: str) -> KernelReceipt:
        """Halt the kernel.

        Args:
            reason: Reason for halting.

        Returns:
            Receipt confirming halt.
        """
        ...

    @abstractmethod
    def export_evidence(self) -> EvidenceBundle:
        """Export the audit ledger as evidence.

        Returns:
            Evidence bundle with full ledger.
        """
        ...


class BaseKernel(Kernel):
    """Base implementation with common kernel functionality.

    Variants extend this class and override specific behaviors.
    """

    def __init__(self, audit_storage: Optional[Any] = None) -> None:
        """Initialize base kernel state.

        Args:
            audit_storage: Optional storage implementing append and
                list_entries. Restored entries are verified before use;
                storage failures must prevent tool execution.
        """
        # Non-blocking, single-flight admission avoids unbounded request waiters.
        self._submit_lock = Lock()
        # Serialises admission vs. halt publication, without waiting on tool execution.
        self._admission_lock = Lock()
        # Coordinate halt-intent writes with the end of single-flight admission:
        # no halt may be stranded between the owner's final check and unlock.
        self._halt_intent_lock = Lock()
        self._pending_halt: Optional[str] = None
        self._config: Optional[KernelConfig] = None
        self._state_machine: Optional[StateMachine] = None
        self._ledger: Optional[AuditLedger] = None
        self._audit_storage = audit_storage
        # Opt-in, strict-only shared global accounting. Never enabled by default.
        # The journal reserves the permit and an operation intent atomically.
        self._shared_permit_journal: Optional[Any] = None
        self._shared_builtin_tools: dict[str, Any] = {}
        self._policy: Optional[JurisdictionPolicy] = None
        self._dispatcher: Optional[Dispatcher] = None
        self._runtime: Optional[KernelRuntime] = None
        self._pending_request: Optional[KernelRequest] = None
        self._pending_decision: Optional[Decision] = None
        self._pending_result: Optional[Any] = None
        self._nonce_registry: NonceRegistry = NonceRegistry()
        self._keyring: dict[str, bytes] = {}  # Legacy local HMAC only
        self._public_verifiers: dict[str, PublicVerificationKey] | None = None
        self._transitions: list[tuple[KernelState, KernelState]] = []
        # Set only after a permit (or the explicit insecure opt-out) has bound
        # the parameters that EXECUTING is allowed to use.
        self._execution_authorised: bool = False
        # Independent of StateMachine.reset(). Halt stays irrevocable.
        self._halted: bool = False

    def enable_shared_permit_accounting(self, journal: Any) -> None:
        """Opt into global PostgreSQL permit accounting before kernel boot.

        This first integration supports *only* the pinned, deterministic
        builtin echo/add handlers in the strict variant. It is a bounded
        execution pilot, NOT a remote provider or production service. The
        PostgreSQL intent is the global accounting authority; the ordinary
        local audit chain remains an additional, non-atomic projection.
        """
        from shards_kernel.distributed.postgres import PostgresPermitJournal

        if self._state_machine is not None:
            raise StateError("Shared accounting must be enabled before boot")
        if not isinstance(journal, PostgresPermitJournal):
            raise TypeError("Shared accounting requires PostgresPermitJournal")
        self._shared_permit_journal = journal

    @property
    def config(self) -> KernelConfig:
        """Return kernel configuration."""
        if self._config is None:
            raise StateError("Kernel not booted")
        return self._config

    @property
    def policy(self) -> JurisdictionPolicy:
        """Return jurisdiction policy."""
        if self._policy is None:
            raise StateError("Kernel not booted")
        return self._policy

    def set_policy(self, policy: JurisdictionPolicy) -> None:
        """Set the jurisdiction policy.

        Args:
            policy: Policy to use.
        """
        self._policy = policy

    def set_keyring(self, keyring: dict[str, bytes]) -> None:
        """Set the HMAC keyring for permit verification.

        Args:
            keyring: Map of key_id -> HMAC secret key (32 bytes recommended).
        """
        if self._public_verifiers is not None:
            raise ValueError("Public-only verifier mode cannot enable HMAC signing secrets")
        self._keyring = dict(keyring)

    def set_public_verifiers(self, keys: dict[str, PublicVerificationKey]) -> None:
        """Use operator-pinned public-only Ed25519 verification; disable HMAC.

        A fresh kernel can switch to public verification. It cannot silently
        re-enable HMAC once public-only mode has been selected.
        Key replacement supports explicit key revocation and rotation.
        """
        if self._keyring:
            raise ValueError("Refusing public-only mode while HMAC secrets are configured")
        if not isinstance(keys, dict) or any(
            not isinstance(key_id, str) or not key_id
            or not isinstance(record, PublicVerificationKey)
            for key_id, record in keys.items()
        ):
            raise ValueError("Expected key-id to PublicVerificationKey mapping")
        self._public_verifiers = dict(keys)

    @property
    def transition_log(self) -> tuple[tuple[KernelState, KernelState], ...]:
        """Return state transitions observed since boot, oldest first."""
        return tuple(self._transitions)

    def load_ledger(self, evidence: EvidenceBundle) -> None:
        """Load a ledger whose hash chain verifies, then rebuild nonce use.

        A bundle whose chain does not recompute is refused and the kernel is
        halted. Entries are not installed in that case, so a forged bundle
        cannot seed the nonce registry or the root hash.

        Successful loads count a permit use for ``INTENT`` records and for
        legacy ``ALLOW`` records. Outcome records are not counted again.

        Args:
            evidence: Evidence bundle containing ledger entries.

        Raises:
            StateError: If the kernel is not booted or is already halted.
            AuditError: If the hash chain does not verify. The kernel is
                HALTED before this is raised.
        """
        if self._ledger is None or self._state_machine is None:
            raise StateError("Kernel not booted")
        if self._halted:
            raise StateError("Kernel is halted")
        self._state_machine.assert_not_halted()

        try:
            if evidence.kernel_id != self.config.kernel_id or evidence.variant != self.config.variant:
                raise AuditError("Evidence kernel identity does not match this kernel")
            self._ledger.load_verified(evidence.ledger_entries, evidence.root_hash)
        except AuditError:
            self._halt_on_fault(
                "Refusing to load a ledger whose hash chain does not verify"
            )
            raise

        self._rebuild_nonce_registry()

    def _rebuild_nonce_registry(self) -> None:
        """Rebuild nonce use from the verified ledger."""
        if self._ledger is None:
            raise StateError("Kernel not booted")
        self._nonce_registry = NonceRegistry()
        for entry in self._ledger.entries:
            if (
                entry.permit_digest
                and entry.permit_verification in ("INTENT", "ALLOW")
                and entry.permit_nonce
                and entry.permit_issuer
                and entry.permit_subject
                and entry.permit_max_executions is not None
            ):
                self._nonce_registry.check_and_record(
                    nonce=entry.permit_nonce,
                    issuer=entry.permit_issuer,
                    subject=entry.permit_subject,
                    permit_id=entry.permit_digest,
                    max_executions=entry.permit_max_executions,
                    current_time_ms=entry.ts_ms,
                )

    def boot(self, config: KernelConfig) -> None:
        """Boot the kernel with configuration."""
        if self._state_machine is not None:
            raise BootError("Kernel already booted")
        if self._shared_permit_journal is not None and (
            config.variant != "strict" or config.allow_insecure_unpermitted_execution
        ):
            raise BootError("Shared permit accounting requires the strict, permitted kernel")

        self._config = config
        self._transitions = []
        self._execution_authorised = False
        self._state_machine = StateMachine(
            KernelState.BOOTING,
            on_transition=self._record_transition,
        )
        self._ledger = AuditLedger(
            config.kernel_id,
            config.variant,
            storage=self._audit_storage,
        )
        if self._ledger.entries:
            self._rebuild_nonce_registry()
        self._policy = self._policy or JurisdictionPolicy.default()
        self._dispatcher = Dispatcher(create_default_registry())
        if self._shared_permit_journal is not None:
            # Pinned tool objects prevent registry substitution between admission
            # and dispatch. No custom/external effects in this pilot.
            self._shared_builtin_tools = {
                name: self._dispatcher.registry.get(name)
                for name in ("echo", "add")
            }
        self._runtime = KernelRuntime(
            self._dispatcher,
            now_ms=self._config.clock.now_ms,
        )

        # Transition to IDLE
        self._state_machine.transition(KernelState.IDLE)

    def get_state(self) -> KernelState:
        """Get the current kernel state."""
        if self._state_machine is None:
            return KernelState.BOOTING
        return self._state_machine.state

    def _record_transition(self, state_from: KernelState, state_to: KernelState) -> None:
        """Remember a transition for tests and diagnostics."""
        self._transitions.append((state_from, state_to))

    def _halt_on_fault(self, reason: str) -> None:
        """Move to HALTED after an unexpected failure. Never raises."""
        if self._state_machine is None:
            return
        self._halted = True
        state_from = self._state_machine.state
        if not self._state_machine.is_halted:
            try:
                self._state_machine.halt()
            except Exception:
                return
        if self._ledger is None or self._config is None:
            return
        try:
            self._ledger.append(
                request_id="HALT",
                actor="SYSTEM",
                intent=reason,
                decision=Decision.HALT,
                state_from=state_from,
                state_to=KernelState.HALTED,
                ts_ms=self.config.clock.now_ms(),
                error=reason,
                audit_phase="halt",
            )
        except Exception:
            return

    def submit(
        self, request: KernelRequest, permit_token: Optional[PermitToken] = None
    ) -> KernelReceipt:
        """Submit a request for processing.

        Only one request enters the state machine at a time. Concurrent
        callers receive an independently audited KERNEL_BUSY denial, rather
        than blocking behind an unbounded handler or corrupting the lifecycle.
        """
        with self._admission_lock:
            admitted = self._submit_lock.acquire(blocking=False)
        if not admitted:
            return self._deny_busy(request)
        try:
            return self._submit_serialized(request, permit_token)
        finally:
            with self._halt_intent_lock:
                try:
                    if self._pending_halt is not None and not self._halted:
                        self._halt_locked(self._pending_halt)
                    elif self._halted:
                        self._pending_halt = None
                finally:
                    self._submit_lock.release()

    def _deny_busy(self, request: KernelRequest) -> KernelReceipt:
        """Audited pre-admission refusal; no permit verification or tool dispatch.

        A BUSY record is not a valid ALLOW/DENY policy evaluation: it records
        rejection at the admission boundary while the state machine is owned
        by an in-flight request. The audit ledger serializes concurrent appends.
        """
        if self._state_machine is None or self._ledger is None or self._config is None:
            raise StateError("Kernel not booted")
        state = self._state_machine.state
        error = "KERNEL_BUSY: single-flight admission in progress"
        try:
            entry = self._ledger.append(
                request_id=request.request_id,
                actor=request.actor,
                intent=request.intent,
                decision=Decision.DENY,
                state_from=state,
                state_to=state,
                ts_ms=self.config.clock.now_ms(),
                error=error,
                audit_phase="outcome",
            )
        except Exception:
            self._quarantine_failed_admission_audit("Admission rejection audit failure")
            raise
        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.REJECTED,
            state_from=state,
            state_to=state,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.DENY,
            error=error,
            evidence_hash=entry.entry_hash,
        )

    def _quarantine_failed_admission_audit(self, reason: str) -> None:
        """Prevent future execution when a pre-admission audit could not commit."""
        with self._admission_lock:
            self._pending_halt = reason
        with self._halt_intent_lock:
            if self._submit_lock.acquire(blocking=False):
                try:
                    if not self._halted:
                        self._halt_on_fault(reason)
                    self._pending_halt = None
                finally:
                    self._submit_lock.release()

    def _submit_serialized(
        self, request: KernelRequest, permit_token: Optional[PermitToken]
    ) -> KernelReceipt:
        """Process a single submission while the caller holds the lock."""
        if (
            self._state_machine is None
            or self._dispatcher is None
            or self._ledger is None
            or self._runtime is None
        ):
            raise StateError("Kernel not booted")

        if self._halted:
            raise StateError("Kernel is halted")
        if self._pending_halt is not None:
            return self._deny_busy(request)
        self._state_machine.assert_not_halted()
        self._state_machine.assert_state(KernelState.IDLE)
        self._execution_authorised = False
        try:
            # PermitToken's nested JSON mappings remain mutable despite the
            # frozen dataclass. Pin one private snapshot before signature
            # verification and preserve it through the final dispatch gate.
            signed_snapshot = copy.deepcopy(permit_token) if permit_token is not None else None
            return self._submit_bound(request, signed_snapshot)
        except Exception:
            self._halt_on_fault("Unhandled exception during request processing")
            raise

    def _tool_parts(
        self, request: KernelRequest
    ) -> tuple[Optional[str], dict[str, Any], Optional[str]]:
        """Return ``(tool_name, tool_params, error)`` for a request."""
        tool_call = request.tool_call
        if tool_call is None:
            return None, {}, None
        if isinstance(tool_call, ToolCall):
            params = tool_call.params
            name: Optional[str] = tool_call.name
        elif isinstance(tool_call, dict):
            params = tool_call.get("params", {})
            name = tool_call.get("name") or ""
        else:
            return None, {}, "Invalid tool call structure"
        if not isinstance(params, dict):
            return name, {}, "PARAM_BINDING_MISMATCH: tool_call.params must be a dictionary"
        return name, params, None

    def _split_dispatch_params(
        self, params: dict[str, Any], handler: Callable[..., Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Separate tool kwargs from additional, still-authorised context."""
        return params, {}

    def _submit_bound(
        self, request: KernelRequest, permit_token: Optional[PermitToken]
    ) -> KernelReceipt:
        """Process one request. Callers wrap this so faults halt the kernel."""
        if (
            self._state_machine is None
            or self._ledger is None
            or self._dispatcher is None
            or self._runtime is None
        ):
            raise StateError("Kernel not booted")

        machine = self._state_machine
        state_from = machine.state
        machine.transition(KernelState.VALIDATING)

        validation_errors = validate_request(request)
        if validation_errors:
            return self._deny_request(
                request,
                state_from,
                f"Validation failed: {'; '.join(validation_errors)}",
            )

        ambiguity_errors = check_ambiguity(
            request,
            max_intent_length=self.config.max_intent_length,
            strict=self._is_strict_ambiguity(),
        )
        # Ambiguity is always denied. fail_closed=False is not an opt-out.
        if ambiguity_errors:
            return self._deny_request(
                request,
                state_from,
                f"Ambiguity detected: {'; '.join(ambiguity_errors)}",
            )

        tool_name, tool_params, tool_error = self._tool_parts(request)
        if tool_error:
            return self._deny_request(request, state_from, tool_error)

        if self._requires_permit(request) and permit_token is not None and tool_name != permit_token.action:
            return self._deny_permit(
                request,
                state_from,
                f"ACTION_TOOL_MISMATCH: permit authorises '{permit_token.action}' but the tool is '{tool_name}'",
                ["ACTION_TOOL_MISMATCH"],
                permit_digest=permit_token.permit_id,
                proposal_hash=permit_token.proposal_hash,
            )

        canonical_params: Optional[dict[str, Any]] = None
        request_bound_params: Optional[dict[str, Any]] = None
        dispatch_params: Optional[dict[str, Any]] = None
        registered_tool = None
        if request.tool_call is not None:
            canonical_params, bind_error = resolve_bound_params(request.params, tool_params)
            if bind_error or canonical_params is None:
                return self._deny_request(
                    request,
                    state_from,
                    bind_error or "PARAM_BINDING_MISMATCH",
                )
            request_bound_params = canonical_params
            dispatch_params = canonical_params
            registered_tool = self._dispatcher.registry.get(tool_name or "")
            if registered_tool is not None:
                tool_params_for_dispatch, context_params = self._split_dispatch_params(
                    request_bound_params, registered_tool.handler
                )
                dispatch_params, bind_error = resolve_effective_params(
                    registered_tool.handler, tool_params_for_dispatch
                )
                if bind_error or dispatch_params is None:
                    return self._deny_request(
                        request, state_from, bind_error or "PARAM_BINDING_MISMATCH"
                    )
                canonical_params = {**dispatch_params, **context_params}

        permit_digest = None
        proposal_hash = None
        permit_nonce = None
        permit_issuer = None
        permit_subject = None
        permit_max_executions = None
        decision_envelope = None

        if self._requires_permit(request):
            if permit_token is None:
                return self._deny_permit(
                    request,
                    state_from,
                    "MISSING_PERMIT",
                    ["MISSING_PERMIT"],
                )
            allowed_actions = self.policy.allowed_tools
            if "*" in allowed_actions:
                allowed_actions = frozenset({permit_token.action, "*"})

            permit_verification_result = verify_permit(
                permit=permit_token,
                keyring=self._keyring,
                # In shared mode the PostgreSQL primary is the sole replay
                # and consumption authority. A process-local cache must
                # never reject *after* the global reservation has committed.
                nonce_registry=(
                    self._nonce_registry
                    if self._shared_permit_journal is None
                    else NonceRegistry()
                ),
                current_time_ms=self.config.clock.now_ms(),
                current_jurisdiction=self.config.jurisdiction,
                allowed_actions=allowed_actions,
                request_actor=request.actor,
                request_params=canonical_params or {},
                request_evidence=request.evidence,
                commit_use=False,
                public_keys=self._public_verifiers,
                expected_audience=self.config.kernel_id,
            )
            permit_digest = permit_token.permit_id
            proposal_hash = permit_token.proposal_hash
            permit_nonce = permit_token.nonce
            permit_issuer = permit_token.issuer
            permit_subject = permit_token.subject
            permit_max_executions = permit_token.max_executions
            if not permit_verification_result.is_allowed():
                return self._deny_permit(
                    request,
                    state_from,
                    "Permit verification failed: "
                    + ", ".join(permit_verification_result.reasons),
                    permit_verification_result.reasons,
                    permit_digest=permit_digest,
                    proposal_hash=proposal_hash,
                )

            max_time = permit_token.constraints.get("max_time_ms")
            forbidden = permit_token.constraints.get("forbidden_params", [])
            decision_envelope = DecisionEnvelope(
                proposal_hash=permit_token.proposal_hash,
                permit_digest=permit_token.permit_id,
                constraints=dict(permit_token.constraints),
                max_time_ms=max_time if isinstance(max_time, int) else None,
                forbidden_params=tuple(forbidden) if isinstance(forbidden, list) else tuple(),
                tool_name=tool_name or "",
                params=dict(canonical_params or {}),
                decision=Decision.ALLOW,
                verified_at_ms=self.config.clock.now_ms(),
                actor=request.actor,
            )

        machine.transition(KernelState.ARBITRATING)

        if self.config.require_jurisdiction:
            policy_result = evaluate_policy(request, self.policy)
            if not policy_result.allowed:
                return self._deny_request(
                    request,
                    state_from,
                    f"Jurisdiction denied: {'; '.join(policy_result.violations)}",
                )

        variant_errors = self._check_variant_requirements(request)
        if variant_errors:
            return self._deny_request(
                request,
                state_from,
                f"Variant requirements not met: {'; '.join(variant_errors)}",
            )

        if request.tool_call is None:
            machine.transition(KernelState.AUDITING)
            entry = self._append_record(
                request,
                state_from=state_from,
                decision=Decision.ALLOW,
                state_to=KernelState.COMPLETED,
                audit_phase="outcome",
            )
            self._complete_request()
            return self._receipt(
                request,
                state_from,
                ReceiptStatus.ACCEPTED,
                Decision.ALLOW,
                entry.entry_hash,
                None,
            )

        live_name, live_params, live_error = self._tool_parts(request)
        rebound, rebound_error = resolve_bound_params(
            request.params if live_error is None else None,
            live_params,
        )
        if (
            live_error
            or rebound_error
            or live_name != tool_name
            or not equal_json_values(rebound, request_bound_params)
            or dispatch_params is None
        ):
            return self._deny_request(
                request,
                state_from,
                rebound_error or live_error or "PARAM_BINDING_MISMATCH",
            )

        if permit_token is not None:
            if tool_name != permit_token.action or not _params_satisfy_permit(
                canonical_params or {}, permit_token.params
            ):
                return self._deny_permit(
                    request,
                    state_from,
                    "PARAM_BINDING_MISMATCH: execution parameters are not those "
                    "the permit authorised",
                    ["PARAM_BINDING_MISMATCH"],
                    permit_digest=permit_digest,
                    proposal_hash=proposal_hash,
                )
        elif not self.config.allow_insecure_unpermitted_execution:
            return self._deny_permit(
                request,
                state_from,
                "MISSING_PERMIT",
                ["MISSING_PERMIT"],
            )

        shared_operation_id: Optional[str] = None
        if self._shared_permit_journal is not None:
            # Never let a permissive/legacy HMAC mode or a dynamically replaced
            # tool reach the distributed accounting and dispatch boundary.
            if permit_token is None or permit_token.version != 2 or self._public_verifiers is None:
                return self._deny_permit(
                    request, state_from, "DISTRIBUTED_REQUIRES_ED25519",
                    ["DISTRIBUTED_REQUIRES_ED25519"],
                )
            if (
                tool_name not in self._shared_builtin_tools
                or registered_tool is not self._shared_builtin_tools[tool_name]
            ):
                return self._deny_request(
                    request, state_from, "DISTRIBUTED_TOOL_NOT_APPROVED"
                )
            shared_operation_id = compute_hash_dict({
                "domain": "SHARDS-SHARED-OPERATION-V1",
                "kernel_id": self.config.kernel_id,
                "actor": request.actor,
                "request_id": request.request_id,
            })
            request_sha256 = compute_hash_dict({
                "domain": "SHARDS-SHARED-REQUEST-V1",
                "operation_id": shared_operation_id,
                "permit_id": permit_token.permit_id,
                "tool_name": tool_name,
                "params": canonical_params,
                "evidence": request.evidence,
                "intent": request.intent,
            })
            # This PostgreSQL transaction consumes the global budget and
            # creates the durable intent together. Any timeout or partition
            # propagates and HALTS the kernel; there is no SQLite fallback.
            reserved = self._shared_permit_journal.reserve(
                operation_id=shared_operation_id,
                permit_id=permit_token.permit_id,
                issuer=permit_token.issuer,
                subject=permit_token.subject,
                nonce=permit_token.nonce,
                max_executions=permit_token.max_executions,
                request_sha256=request_sha256,
            )
            if not reserved:
                return self._deny_permit(
                    request, state_from, "GLOBAL_PERMIT_EXHAUSTED_OR_DUPLICATE",
                    ["GLOBAL_PERMIT_EXHAUSTED_OR_DUPLICATE"],
                    permit_digest=permit_digest, proposal_hash=proposal_hash,
                )

        # The local intent is an extra audit projection. The globally
        # authoritative reservation was already committed to PostgreSQL.
        # If this append fails, the budget stays spent and dispatch stops.
        machine.transition(KernelState.AUDITING)
        self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=Decision.ALLOW,
            state_from=state_from,
            state_to=KernelState.EXECUTING,
            ts_ms=self.config.clock.now_ms(),
            tool_name=tool_name,
            params=canonical_params,
            evidence=request.evidence,
            permit_digest=permit_digest,
            permit_verification="INTENT" if permit_token is not None else None,
            permit_denial_reasons=tuple(),
            proposal_hash=proposal_hash,
            permit_nonce=permit_nonce,
            permit_issuer=permit_issuer,
            permit_subject=permit_subject,
            permit_max_executions=permit_max_executions,
            audit_phase="intent",
        )

        if permit_token is not None and self._shared_permit_journal is None:
            consumed = self._nonce_registry.check_and_record(
                nonce=permit_token.nonce,
                issuer=permit_token.issuer,
                subject=permit_token.subject,
                permit_id=permit_token.permit_id,
                max_executions=permit_token.max_executions,
                current_time_ms=self.config.clock.now_ms(),
            )
            if not consumed:
                return self._fail_request(
                    request,
                    state_from,
                    "REPLAY_DETECTED",
                    params=canonical_params,
                    tool_name=tool_name,
                    permit_digest=permit_digest,
                    proposal_hash=proposal_hash,
                    denial_reasons=["REPLAY_DETECTED"],
                )

        self._execution_authorised = True
        self._transition_executing()
        if shared_operation_id is not None:
            if not self._shared_permit_journal.mark_dispatched(shared_operation_id):
                raise AuditError("Shared operation dispatch gate refused execution")
        context = ExecutionContext(
            trace_id=request.request_id,
            actor=request.actor,
            state_ref=machine.state.value,
            policy_ref="jurisdiction:active",
            policy_snapshot=(
                f"actors={sorted(self.policy.allowed_actors)};"
                f"tools={sorted(self.policy.allowed_tools)}"
            ),
            idempotency_key=request.request_id,
            max_time_ms=(
                decision_envelope.max_time_ms if decision_envelope is not None else None
            ),
            max_calls=1,
            call_index=1,
        )
        runtime_result = self._runtime.execute(
            ToolCall(name=tool_name or "", params=copy.deepcopy(dispatch_params)),
            context,
            authorised_params=copy.deepcopy(dispatch_params),
            authorised_tool_name=tool_name,
            authorised_tool=registered_tool,
            authorisation_deadline_ms=(permit_token.valid_until_ms if permit_token is not None else None),
        )
        if not runtime_result.dispatcher_result.success:
            if shared_operation_id is not None:
                # A failed invocation might still have applied a side effect.
                # Preserve budget consumption and quarantine it for review.
                if not self._shared_permit_journal.mark_unknown(shared_operation_id):
                    raise AuditError("Could not mark failed operation UNKNOWN")
            return self._fail_request(
                request,
                state_from,
                f"Tool execution failed: {runtime_result.dispatcher_result.error}",
                params=canonical_params,
                tool_name=tool_name,
                permit_digest=permit_digest,
                proposal_hash=proposal_hash,
            )

        machine.transition(KernelState.AUDITING)
        entry = self._append_record(
            request,
            state_from=state_from,
            decision=Decision.ALLOW,
            state_to=KernelState.COMPLETED,
            audit_phase="outcome",
            tool_name=tool_name,
            params=canonical_params,
            permit_digest=permit_digest,
            permit_verification="OUTCOME" if permit_token is not None else None,
            proposal_hash=proposal_hash,
            permit_nonce=permit_nonce,
            permit_issuer=permit_issuer,
            permit_subject=permit_subject,
            permit_max_executions=permit_max_executions,
        )
        if shared_operation_id is not None:
            # Only deterministic builtins are reachable in this pilot, so the
            # locally witnessed audit outcome is sufficient to close the
            # internal operation. External providers require independent
            # confirmation and must NOT use this reconciliation path.
            if not self._shared_permit_journal.reconcile(
                shared_operation_id,
                outcome="SUCCEEDED",
                evidence_ref=entry.entry_hash,
                provider_ref="builtin:" + shared_operation_id,
            ):
                raise AuditError("Could not reconcile committed builtin outcome")
        self._complete_request()
        return self._receipt(
            request,
            state_from,
            ReceiptStatus.ACCEPTED,
            Decision.ALLOW,
            entry.entry_hash,
            runtime_result.dispatcher_result.result,
        )

    def _transition_executing(self) -> None:
        """Enter EXECUTING only when parameters have been bound."""
        if self._state_machine is None:
            raise StateError("Kernel not booted")
        if not self._execution_authorised:
            raise StateError("Refusing EXECUTING without a bound authorisation")
        self._state_machine.transition(KernelState.EXECUTING)

    def _complete_request(self) -> None:
        """Leave AUDITING through COMPLETED and return to IDLE."""
        if self._state_machine is None:
            raise StateError("Kernel not booted")
        if self._state_machine.state == KernelState.AUDITING:
            self._state_machine.transition(KernelState.COMPLETED)
        if self._state_machine.state != KernelState.COMPLETED:
            raise StateError(
                f"Cannot complete request from {self._state_machine.state.value}"
            )
        self._state_machine.transition(KernelState.IDLE)

    def step(self) -> Optional[KernelReceipt]:
        """Advance the kernel by one step."""
        return None

    def halt(self, reason: str) -> KernelReceipt:
        """Atomically publish an operator halt before a new admission can start.

        A queued halt is committed to the ledger while holding the same
        intent lock used by the active submitter's final check AND unlock.
        Once published, later callers cannot dispatch before terminal halt.
        An in-flight handler is not forcibly interrupted; its effect outcome
        must be audited before the terminal transition.
        """
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")

        # First publish the halt through the same lock that admits new work.
        # A pending halt stays visible even if another submitter currently owns
        # the finalisation lock; later admission can only fail closed.
        with self._admission_lock:
            if self._halted:
                raise StateError("Kernel is halted")
            self._pending_halt = reason

        with self._halt_intent_lock:
            if self._halted:
                return KernelReceipt(
                    request_id="HALT",
                    status=ReceiptStatus.ACCEPTED,
                    state_from=KernelState.HALTED,
                    state_to=KernelState.HALTED,
                    ts_ms=self.config.clock.now_ms(),
                    decision=Decision.HALT,
                    error="HALT_ALREADY_EFFECTIVE",
                    evidence_hash=self._ledger.root_hash,
                )
            if self._submit_lock.acquire(blocking=False):
                try:
                    return self._halt_locked(reason)
                finally:
                    self._submit_lock.release()

            state = self._state_machine.state
            try:
                entry = self._ledger.append(
                    request_id="HALT",
                    actor="SYSTEM",
                    intent=reason,
                    decision=Decision.HALT,
                    state_from=state,
                    state_to=state,
                    ts_ms=self.config.clock.now_ms(),
                    error="HALT_QUEUED",
                    audit_phase="halt",
                )
            except Exception:
                # Preserve fail-closed admission even when the queued record
                # cannot be persisted. The submitter's finalisation enforces
                # terminal halt when it next acquires the intent lock.
                self._pending_halt = "Operator halt audit failure"
                raise

            # If the submitter released admission between our first failed
            # attempt and the audit commit, finalise the halt here. Otherwise
            # the submitter finalises immediately after its own outcome audit.
            if self._submit_lock.acquire(blocking=False):
                try:
                    if not self._halted:
                        # The in-flight request released admission before we
                        # returned: report terminal completion, not deferral.
                        return self._halt_locked(reason)
                    self._pending_halt = None
                    return KernelReceipt(
                        request_id="HALT",
                        status=ReceiptStatus.ACCEPTED,
                        state_from=KernelState.HALTED,
                        state_to=KernelState.HALTED,
                        ts_ms=self.config.clock.now_ms(),
                        decision=Decision.HALT,
                        error="HALT_ALREADY_EFFECTIVE",
                        evidence_hash=self._ledger.root_hash,
                    )
                finally:
                    self._submit_lock.release()
            return KernelReceipt(
                request_id="HALT",
                status=ReceiptStatus.QUEUED,
                state_from=state,
                state_to=state,
                ts_ms=self.config.clock.now_ms(),
                decision=Decision.HALT,
                error="HALT_QUEUED",
                evidence_hash=entry.entry_hash,
            )

    def _halt_locked(self, reason: str) -> KernelReceipt:
        """Finalize terminal halt only while holding the admission lock."""
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")
        self._pending_halt = None
        self._halted = True
        state_from = self._state_machine.state
        self._state_machine.halt()
        entry = self._ledger.append(
            request_id="HALT",
            actor="SYSTEM",
            intent=reason,
            decision=Decision.HALT,
            state_from=state_from,
            state_to=KernelState.HALTED,
            ts_ms=self.config.clock.now_ms(),
            audit_phase="halt",
        )
        return KernelReceipt(
            request_id="HALT",
            status=ReceiptStatus.ACCEPTED,
            state_from=state_from,
            state_to=KernelState.HALTED,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.HALT,
            evidence_hash=entry.entry_hash,
        )

    def export_evidence(self) -> EvidenceBundle:
        """Export the audit ledger as evidence."""
        if self._ledger is None:
            raise StateError("Kernel not booted")
        return self._ledger.export(self.config.clock.now_ms())

    def _append_record(
        self,
        request: KernelRequest,
        *,
        state_from: KernelState,
        decision: Decision,
        state_to: KernelState,
        audit_phase: str,
        tool_name: Optional[str] = None,
        params: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
        permit_digest: Optional[str] = None,
        permit_verification: Optional[str] = None,
        permit_denial_reasons: Optional[tuple[str, ...]] = None,
        proposal_hash: Optional[str] = None,
        permit_nonce: Optional[str] = None,
        permit_issuer: Optional[str] = None,
        permit_subject: Optional[str] = None,
        permit_max_executions: Optional[int] = None,
    ) -> Any:
        """Append one audit record. The ledger hashes ``params`` as given."""
        if self._ledger is None:
            raise StateError("Kernel not booted")
        return self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=decision,
            state_from=state_from,
            state_to=state_to,
            ts_ms=self.config.clock.now_ms(),
            tool_name=tool_name,
            params=params,
            evidence=request.evidence,
            error=error,
            permit_digest=permit_digest,
            permit_verification=permit_verification,
            permit_denial_reasons=permit_denial_reasons,
            proposal_hash=proposal_hash,
            permit_nonce=permit_nonce,
            permit_issuer=permit_issuer,
            permit_subject=permit_subject,
            permit_max_executions=permit_max_executions,
            audit_phase=audit_phase,
        )

    def _receipt(
        self,
        request: KernelRequest,
        state_from: KernelState,
        status: ReceiptStatus,
        decision: Decision,
        evidence_hash: Optional[str],
        tool_result: Any,
        error: Optional[str] = None,
    ) -> KernelReceipt:
        """Build a receipt. The kernel is IDLE again unless it halted."""
        return KernelReceipt(
            request_id=request.request_id,
            status=status,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            decision=decision,
            error=error,
            evidence_hash=evidence_hash,
            tool_result=tool_result,
        )

    def _deny_request(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
    ) -> KernelReceipt:
        """Create a DENY receipt and audit entry."""
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)
        entry = self._append_record(
            request,
            state_from=state_from,
            decision=Decision.DENY,
            state_to=KernelState.COMPLETED,
            audit_phase="outcome",
            error=error,
        )
        self._complete_request()
        return self._receipt(
            request,
            state_from,
            ReceiptStatus.REJECTED,
            Decision.DENY,
            entry.entry_hash,
            None,
            error=error,
        )

    def _fail_request(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
        *,
        params: Optional[dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        permit_digest: Optional[str] = None,
        proposal_hash: Optional[str] = None,
        denial_reasons: Optional[list[str]] = None,
    ) -> KernelReceipt:
        """Create a FAILED receipt. The audited params are the ones bound."""
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)
        entry = self._append_record(
            request,
            state_from=state_from,
            decision=Decision.DENY,
            state_to=KernelState.COMPLETED,
            audit_phase="outcome",
            tool_name=tool_name,
            params=params,
            error=error,
            permit_digest=permit_digest,
            permit_verification="OUTCOME" if permit_digest else None,
            permit_denial_reasons=tuple(denial_reasons or ()),
            proposal_hash=proposal_hash,
        )
        self._complete_request()
        return self._receipt(
            request,
            state_from,
            ReceiptStatus.FAILED,
            Decision.DENY,
            entry.entry_hash,
            None,
            error=error,
        )

    def _is_strict_ambiguity(self) -> bool:
        """Return whether strict ambiguity checking is enabled."""
        return True

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Check variant-specific requirements. Override in variants."""
        return []

    def _requires_permit(self, request: KernelRequest) -> bool:
        """Return whether this request must carry a verified permit.

        A tool call requires a permit even when no keyring is configured.
        ``allow_insecure_unpermitted_execution`` is the only opt-out, and
        StrictKernel forces that flag off. Intent-only requests do not
        execute a tool and do not require a permit.
        """
        if request.tool_call is None:
            return False
        return not self.config.allow_insecure_unpermitted_execution

    def _deny_permit(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
        denial_reasons: list[str],
        permit_digest: Optional[str] = None,
        proposal_hash: Optional[str] = None,
    ) -> KernelReceipt:
        """Create a DENY receipt for permit verification failure.

        Permit denial does not record a nonce use.
        """
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)
        entry = self._append_record(
            request,
            state_from=state_from,
            decision=Decision.DENY,
            state_to=KernelState.COMPLETED,
            audit_phase="outcome",
            error=error,
            permit_digest=permit_digest,
            permit_verification="DENY",
            permit_denial_reasons=tuple(denial_reasons),
            proposal_hash=proposal_hash,
        )
        self._complete_request()
        return self._receipt(
            request,
            state_from,
            ReceiptStatus.REJECTED,
            Decision.DENY,
            entry.entry_hash,
            None,
            error=error,
        )

    def set_runtime_hooks(
        self,
        *,
        before_execute: Optional[
            Callable[[ExecutionContext, ToolCall], Optional[str]]
        ] = None,
        after_execute: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        on_error: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        event_sink: Optional[Callable[[RuntimeEvent], None]] = None,
    ) -> None:
        """Configure runtime hooks for execution mediation observability."""
        if self._runtime is None:
            raise StateError("Kernel not booted")
        self._runtime.set_hooks(
            before_execute=before_execute,
            after_execute=after_execute,
            on_error=on_error,
            event_sink=event_sink,
        )
