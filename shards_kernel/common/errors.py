"""Error definitions for Kernels.

All errors are fail-closed by default. When an error occurs, the kernel
transitions to a safe state (HALTED or returns DENY) rather than proceeding
with potentially unsafe execution.
"""


class KernelError(Exception):
    """Base exception for all kernel errors.

    All kernel errors result in fail-closed behavior. The kernel will not
    proceed with execution when any KernelError is raised.
    """

    def __init__(self, message: str, fail_closed: bool = True) -> None:
        """Initialize kernel error.

        Args:
            message: Human-readable error description.
            fail_closed: Whether this error triggers fail-closed behavior.
                        Defaults to True.
        """
        super().__init__(message)
        self.fail_closed = fail_closed


class BootError(KernelError):
    """Raised when kernel fails to boot.

    Boot errors occur during kernel initialization and prevent the kernel
    from reaching IDLE state. Common causes include invalid configuration
    or missing required parameters.
    """

    pass


class StateError(KernelError):
    """Raised when an invalid state transition is attempted.

    State errors occur when the kernel attempts a transition that violates
    the state machine definition. This indicates a programming error or
    an attempt to bypass the state machine.
    """

    pass


class JurisdictionError(KernelError):
    """Raised when a request fails jurisdiction checks.

    Jurisdiction errors occur when a request attempts to perform an action
    outside the allowed boundaries. This includes unauthorized actors,
    disallowed tools, or missing required fields.
    """

    pass


class AmbiguityError(KernelError):
    """Raised when a request is ambiguous.

    Ambiguity errors occur when a request cannot be unambiguously interpreted.
    This includes empty intents, overly long intents, missing tool names,
    or malformed parameters.
    """

    pass


class ToolError(KernelError):
    """Raised when tool execution fails.

    Tool errors occur during the execution phase when a tool cannot complete
    its operation. This includes unknown tools, invalid parameters, or
    execution failures.
    """

    pass


class AuditError(KernelError):
    """Raised when audit operations fail.

    Audit errors occur when the audit ledger cannot be updated or verified.
    This includes hash chain violations, serialization failures, or
    storage errors.
    """

    pass


class ValidationError(KernelError):
    """Raised when request validation fails.

    Validation errors occur when a request does not meet the required
    schema or format. This includes missing fields, invalid types, or
    constraint violations.
    """

    pass


class ExecutionError(KernelError):
    """Raised when tool execution fails.

    Execution errors occur during the execution phase when a tool
    encounters an error during operation.
    """

    pass


class PermitError(KernelError):
    """Raised when permit verification fails.

    Permit errors occur during the validation phase when a permit token
    cannot be verified or is missing when required. This includes:
    - Missing permit when required (MISSING_PERMIT)
    - Invalid signature (SIGNATURE_INVALID)
    - Expired permit (EXPIRED)
    - Replay attempts (REPLAY_DETECTED)
    - Jurisdiction/action/subject mismatches

    All permit errors result in DENY with reason codes for audit trail.
    """

    pass
