"""Permissive kernel variant implementation.

The permissive kernel has relaxed constraints:
- Still deterministic but less strict ambiguity thresholds
- Can accept intent-only requests (no tool call)
- Audits and returns ALLOW without executing tools for intent-only requests
"""

from kernels.common.types import (
    KernelConfig,
    KernelRequest,
)
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.variants.base import BaseKernel


class PermissiveKernel(BaseKernel):
    """Permissive kernel with relaxed enforcement.

    This variant:
    - Uses relaxed ambiguity thresholds
    - Accepts intent-only requests without tool_call
    - Returns ALLOW for valid intent-only requests without execution
    - Still maintains audit trail for all operations
    """

    VARIANT_NAME = "permissive"

    def __init__(self) -> None:
        """Initialize permissive kernel."""
        super().__init__()
        # Set permissive policy
        self._policy = JurisdictionPolicy(
            allowed_actors=frozenset({"*"}),
            allowed_tools=frozenset({"*"}),
            allow_intent_only=True,
            max_intent_length=8192,  # More permissive
        )

    def boot(self, config: KernelConfig) -> None:
        """Boot with permissive configuration."""
        permissive_config = KernelConfig(
            kernel_id=config.kernel_id,
            variant=self.VARIANT_NAME,
            fail_closed=config.fail_closed,
            require_jurisdiction=config.require_jurisdiction,
            require_audit=config.require_audit,
            clock=config.clock,
            hash_alg=config.hash_alg,
            max_param_bytes=config.max_param_bytes,
            max_intent_length=8192,  # More permissive
            jurisdiction=config.jurisdiction,
            allow_insecure_unpermitted_execution=(
                config.allow_insecure_unpermitted_execution
            ),
        )
        super().boot(permissive_config)

    def _is_strict_ambiguity(self) -> bool:
        """Permissive kernel uses relaxed ambiguity checking."""
        return False

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Permissive kernel allows intent-only requests."""
        # No additional requirements - intent-only is allowed
        return []
