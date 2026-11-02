"""Optimised (-O) Python runtime guard probe for signed ingress checkpoints.

CI invokes this file directly using `python -O`. It must never rely on
assert statements, network access, secrets or shell/subprocess execution.
"""

from pathlib import Path
from types import SimpleNamespace

from shards_kernel.integrations.mtls_ingress import MTLSIngressServer


def main() -> int:
    for missing in (
        "checkpoint_db_file",
        "ingress_id",
        "policy_digest",
        "_checkpoint_identity",
    ):
        ingress = object.__new__(MTLSIngressServer)
        ingress.config = SimpleNamespace(
            revision=1,
            checkpoint_db_file=Path("/nonexistent/checkpoint.sqlite3"),
            ingress_id="ci-test-ingress",
            policy_digest="a" * 64,
        )
        ingress._checkpoint_identity = (10, 20)
        if missing == "_checkpoint_identity":
            ingress._checkpoint_identity = None
        else:
            setattr(ingress.config, missing, None)
        try:
            ingress._verify_policy_checkpoint()
        except ValueError as exc:
            if str(exc) == "Missing signed ingress checkpoint authority":
                continue
        raise SystemExit("Optimised Python bypassed ingress trust field: " + missing)
    print("Optimised Python: all ingress checkpoint authority guards enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
