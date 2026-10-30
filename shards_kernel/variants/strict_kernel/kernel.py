"""Strict kernel variant implementation.

The strict kernel enforces maximum constraints:
- fail_closed is always True
- requires jurisdiction and audit
- strict ambiguity heuristics
- tool execution only if tool_call present and validated
"""

from shards_kernel.common.types import KernelConfig, KernelRequest
from shards_kernel.variants.base import BaseKernel


class StrictKernel(BaseKernel):
    """Strict kernel with maximum enforcement.

    This variant:
    - Always operates in fail-closed mode
    - Requires jurisdiction checks for all requests
    - Requires audit for all operations
    - Uses strict ambiguity detection
    - Only executes tools when tool_call is explicitly provided
    """

    VARIANT_NAME = "strict"

    def boot(self, config: KernelConfig) -> None:
        """Boot with strict configuration enforcement."""
        # Enforce strict settings
        strict_config = KernelConfig(
            kernel_id=config.kernel_id,
            variant=self.VARIANT_NAME,
            fail_closed=True,  # Always true for strict
            require_jurisdiction=True,  # Always true for strict
            require_audit=True,  # Always true for strict
            clock=config.clock,
            hash_alg=config.hash_alg,
            max_param_bytes=config.max_param_bytes,
            max_intent_length=config.max_intent_length,
            jurisdiction=config.jurisdiction,
            # The strict variant cannot be opted out of permit enforcement.
            allow_insecure_unpermitted_execution=False,
        )
        super().boot(strict_config)

    def _is_strict_ambiguity(self) -> bool:
        """Strict kernel uses strict ambiguity checking."""
        return True

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Strict kernel has no additional requirements beyond base."""
        return []
