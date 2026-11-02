# Ed25519 v2 permits — public-only verifier boundary

This feature is an **additive reference implementation** for Shards-Kernel
permit signing. It separates a trusted operator issuer process from the
kernel's verifier. The kernel does not hold the issuer's private key.

## Trust boundaries

```text
  TRUSTED ISSUER PROCESS                    SHARDS-KERNEL
  ┌─────────────────────────┐               ┌───────────────────────┐
  │ Operator review/approval│               │ PublicVerificationKey │
  │ Private Ed25519 key     │──v2 permit───>│ Verify Ed25519        │
  │ sign_v2_permit()        │               │ Policy + nonce + audit│
  └─────────────────────────┘               └───────────────────────┘
```

- Use `python -m pip install -e ".[crypto]"` or install the package with its
  `crypto` extra in the verifier. The underlying implementation uses
  maintained `cryptography`, not hand-written Ed25519.
- The old v1 `HS256` permit remains supported for existing local integrations.
  HMAC and Ed25519 are **mutually exclusive per kernel instance**. The
  kernel rejects a v1 permit in public-only mode and a v2 permit in HMAC mode.
- Public key configuration is explicit and pinned by `key_id`. Its metadata
  binds **issuer** and **audience (kernel ID)**. A key is never discovered from
  an untrusted permit or supplied by an AI model.
- v2 includes `version=2`, `algorithm=Ed25519` and `audience` in its
  signed canonical JSON. The signature message is domain-separated using
  `SHARDS-PERMIT-ED25519-V2` plus a single zero byte prefix separator.
  All legacy v1 signatures and permit IDs remain unchanged.
- `PublicVerificationKey(revoked=True)` and explicit keyring replacement
  support operator-controlled key revocation and overlapping key rotation.
  These records are **not** a durable KMS or revocation distribution service.

## Example: separate issuance and verification

This is a local **test illustration**. In deployment, the private key and the
issuer code run in a separate trusted process with separate credentials and
human/operator approval. Never pass an issuer private key into an MCP tool
or a language-model prompt.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey
from shards_kernel.variants.strict_kernel import StrictKernel

# Issuer side (SEPARATE TRUSTED PROCESS in production)
private_key = Ed25519PrivateKey.generate()
public_key_bytes = private_key.public_key().public_bytes_raw()
unsigned = (
    PermitBuilder()
    .issuer("operator")
    .subject("agent-one")
    .jurisdiction("default")
    .action("echo")
    .params({"text": "approved"})
    .valid_from_ms(0)
    .valid_until_ms(10000)
    .proposal_hash("approval-reference")
    .build_unsigned_v2(key_id="operator-key-1", audience="example-kernel")
)
permit = sign_v2_permit(unsigned, private_key)
wire_payload = permit_to_mapping(permit)

# Verifier side (PUBLIC KEY ONLY)
kernel = StrictKernel()
kernel.boot(KernelConfig(kernel_id="example-kernel", variant="strict", clock=VirtualClock(1000)))
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"agent-one"}),
    allowed_tools=frozenset({"echo"}),
))
kernel.set_public_verifiers({
    "operator-key-1": PublicVerificationKey(
        issuer="operator", audience="example-kernel", public_key=public_key_bytes
    )
})
assert kernel._keyring == {}
# A real caller sends wire_payload via MCP or authenticated HTTP; the
# kernel independently authorises actor/action/params/time/replay on submit.
```

`VirtualClock` is appropriate *only* for this deterministic example; use
`SystemClock` in a service and supply proper trusted transport identity.

## Explicit release blockers

This does **not** fully close #68. It provides working public-key verification
and a separate issuer helper. Production still requires:
1. A separately deployed issuer with operator approval, private-key protection
   through KMS/HSM or equivalent, and authenticated issuance audit.
2. Trusted identities for agents and authenticated binding of the request
   actor to the principal at the remote gateway. The `actor` field is not
   itself an identity proof.
3. Transactional nonce/replay storage across replicas and restarts.
4. Durable, authenticated key rotation/revocation distribution, audit and
   migration policy; fail-closed revocation propagation.
5. A real cross-process MCP end-to-end test with sealed evidence and rollback.
6. A signed versioned policy/configuration. A verifier compromise could still
   alter trusted policy or approved tools unless the runtime is isolated.

Never expose the existing local sample's shared HMAC secret to other agents.
