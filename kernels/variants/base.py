"""Base kernel protocol and abstract implementation.

All kernel variants must implement the Kernel protocol. The BaseKernel
provides common functionality that variants can extend.
"""

import copy
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from kernels.common.types import (
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
from kernels.common.errors import (
    AuditError,
    BootError,
    StateError,
)
from kernels.common.validate import validate_request, check_ambiguity
from kernels.audit.ledger import AuditLedger
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.jurisdiction.rules import evaluate_policy
from kernels.state.machine import StateMachine
from kernels.execution.tools import create_default_registry
from kernels.execution.dispatcher import Dispatcher, resolve_bound_params
from kernels.core.runtime import (
    ExecutionContext,
    KernelRuntime,
    RuntimeEvent,
    RuntimeExecutionResult,
)
from kernels.permits import (
    NonceRegistry,
    PermitToken,
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
        self._config: Optional[KernelConfig] = None
        self._state_machine: Optional[StateMachine] = None
        self._ledger: Optional[AuditLedger] = None
        self._audit_storage = audit_storage
        self._policy: Optional[JurisdictionPolicy] = None
        self._dispatcher: Optional[Dispatcher] = None
        self._runtime: Optional[KernelRuntime] = None
        self._pending_request: Optional[KernelRequest] = None
        self._pending_decision: Optional[Decision] = None
        self._pending_result: Optional[Any] = None
        self._nonce_registry: NonceRegistry = NonceRegistry()
        self._keyring: dict[str, bytes] = {}  # HMAC keys for permit verification
        self._transitions: list[tuple[KernelState, KernelState]] = []
        # Set only after a permit (or the explicit insecure opt-out) has bound
        # the parameters that EXECUTING is allowed to use.
        self._execution_authorised: bool = False
        # Independent of StateMachine.reset(). Halt stays irrevocable.
        self._halted: bool = False

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
        self._keyring = keyring

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
        if self._state_machine is not None and not self._state_machine.is_halted:
            raise BootError("Kernel already booted")

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

        An unexpected exception halts the kernel. A tool call is not run
        unless its parameters were bound and an intent audit record was
        appended first.
        """
        if (
            self._state_machine is None
            or self._dispatcher is None
            or self._ledger is None
            or self._runtime is None
        ):
            raise StateError("Kernel not booted")

        if self._halted:
            raise StateError("Kernel is halted")
        self._state_machine.assert_not_halted()
        self._state_machine.assert_state(KernelState.IDLE)
        self._execution_authorised = False
        try:
            return self._submit_bound(request, permit_token)
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

        canonical_params: Optional[dict[str, Any]] = None
        if request.tool_call is not None:
            canonical_params, bind_error = resolve_bound_params(request.params, tool_params)
            if bind_error or canonical_params is None:
                return self._deny_request(
                    request,
                    state_from,
                    bind_error or "PARAM_BINDING_MISMATCH",
                )

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
            if tool_name != permit_token.action:
                return self._deny_permit(
                    request,
                    state_from,
                    (
                        "ACTION_TOOL_MISMATCH: permit authorises "
                        f"'{permit_token.action}' but the tool is '{tool_name}'"
                    ),
                    ["ACTION_TOOL_MISMATCH"],
                    permit_digest=permit_token.permit_id,
                    proposal_hash=permit_token.proposal_hash,
                )

            allowed_actions = self.policy.allowed_tools
            if "*" in allowed_actions:
                allowed_actions = frozenset({permit_token.action, "*"})

            permit_verification_result = verify_permit(
                permit=permit_token,
                keyring=self._keyring,
                nonce_registry=self._nonce_registry,
                current_time_ms=self.config.clock.now_ms(),
                current_jurisdiction=self.config.jurisdiction,
                allowed_actions=allowed_actions,
                request_actor=request.actor,
                request_params=canonical_params or {},
                request_evidence=request.evidence,
                commit_use=False,
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
            or rebound != canonical_params
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

        # The intent record is appended before the tool is invoked. If this
        # append fails, the exception propagates and the tool does not run.
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

        if permit_token is not None:
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
            ToolCall(name=tool_name or "", params=copy.deepcopy(canonical_params)),
            context,
            authorised_params=copy.deepcopy(canonical_params),
            authorised_tool_name=tool_name,
        )
        if not runtime_result.dispatcher_result.success:
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
        """Halt the kernel."""
        if self._state_machine is None or self._ledger is None:
            raise StateError("Kernel not booted")

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
