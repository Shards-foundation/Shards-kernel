"""Evidence-first kernel variant implementation.

The evidence-first kernel requires evidence for ALLOW decisions:
- Requires evidence field in KernelRequest for ALLOW
- Denies if evidence missing (except halt)
- Emphasizes audit and export capabilities
"""

from kernels.common.types import KernelConfig, KernelRequest
from kernels.variants.base import BaseKernel


class EvidenceFirstKernel(BaseKernel):
    """Evidence-first kernel requiring evidence for all allowed operations.

    This variant:
    - Requires the evidence field to be present for ALLOW decisions
    - Denies requests missing evidence
    - Halt operations do not require evidence
    - Emphasizes comprehensive audit trail
    """

    VARIANT_NAME = "evidence-first"

    def boot(self, config: KernelConfig) -> None:
        """Boot with evidence-first configuration."""
        evidence_config = KernelConfig(
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
        super().boot(evidence_config)

    def _is_strict_ambiguity(self) -> bool:
        """Evidence-first kernel uses strict ambiguity checking."""
        return True

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Evidence-first kernel requires evidence field."""
        errors = []

        # Evidence is required for all requests
        if request.evidence is None:
            errors.append("Evidence field is required for this kernel variant")
        elif not request.evidence.strip():
            errors.append("Evidence field cannot be empty")

        return errors
