"""Dual-channel kernel variant implementation.

The dual-channel kernel requires both intent and constraints:
- Requires request.intent plus a "constraints" dict inside params
- Constraints must include: scope, non_goals, success_criteria
- Denies if constraints missing
- Produces richer receipts with constraint information
"""

from kernels.common.types import KernelConfig, KernelRequest
from kernels.variants.base import BaseKernel


REQUIRED_CONSTRAINT_KEYS = frozenset({"scope", "non_goals", "success_criteria"})


class DualChannelKernel(BaseKernel):
    """Dual-channel kernel requiring intent and constraints.

    This variant:
    - Requires both intent and a constraints dict in params
    - Constraints must include scope, non_goals, and success_criteria
    - Denies requests missing required constraint keys
    - Enables richer decision context through dual-channel input
    """

    VARIANT_NAME = "dual-channel"

    def boot(self, config: KernelConfig) -> None:
        """Boot with dual-channel configuration."""
        dual_config = KernelConfig(
            kernel_id=config.kernel_id,
            variant=self.VARIANT_NAME,
            fail_closed=True,
            require_jurisdiction=True,
            require_audit=True,
            clock=config.clock,
            hash_alg=config.hash_alg,
            max_param_bytes=config.max_param_bytes,
            max_intent_length=config.max_intent_length,
            jurisdiction=config.jurisdiction,
            allow_insecure_unpermitted_execution=(
                config.allow_insecure_unpermitted_execution
            ),
        )
        super().boot(dual_config)

    def _is_strict_ambiguity(self) -> bool:
        """Dual-channel kernel uses strict ambiguity checking."""
        return True

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Dual-channel kernel requires constraints in params."""
        errors = []

        # Check for constraints in params
        if request.params is None:
            errors.append("Params with constraints dict is required")
            return errors

        constraints = request.params.get("constraints")
        if constraints is None:
            errors.append("Constraints dict is required in params")
            return errors

        if not isinstance(constraints, dict):
            errors.append("Constraints must be a dictionary")
            return errors

        # Check for required constraint keys
        missing_keys = REQUIRED_CONSTRAINT_KEYS - set(constraints.keys())
        if missing_keys:
            errors.append(
                f"Missing required constraint keys: {', '.join(sorted(missing_keys))}"
            )

        # Validate constraint values are not empty
        for key in REQUIRED_CONSTRAINT_KEYS:
            if key in constraints:
                value = constraints[key]
                if value is None or (isinstance(value, str) and not value.strip()):
                    errors.append(f"Constraint '{key}' cannot be empty")

        return errors
