# Offline approver → issuer → kernel permit handoff

This is a **two-party offline reference workflow**, not a KMS/HSM-backed
production signing service. It is intentionally **not exposed over MCP, HTTP,
a web endpoint, or to an AI model**. Both private keys must remain protected
in separate operator-owned environments. Agents only receive the resulting
signed permit; Shards-Kernel only receives the issuer's pinned public key.

## Authority boundary

```text
Untrusted agent proposes draft (unsigned v2, exact action/params/subject)
               |
    Trusted human approver reviews the full JSON
       [Ed25519 approval key in separate custody]
               |
   SIGNED approval of canonical draft SHA256 and short UTC time window
               |
       Offline issuer validates approval with independently pinned
       APPROVER PUBLIC KEY (never read from approval JSON)
       [DIFFERENT Ed25519 private key in separate issuer custody]
               |
        Signed, audience-bound, one-execution v2 permit
               |
   Shards-Kernel: pinned public issuer key + exact action/subject/params,
   expiry, strict jurisdiction and persistent audit/replay
```

The two signing keys **MUST** differ. The approver signature covers the
hash of canonical unsigned permit bytes, binding all permit fields:
`subject`, `issuer`, `key_id`, `audience`, `action`, `params`,
validity, nonce and proposal hash. The issuer also checks operator-provided
expected issuer/key ID and refuses signatures outside the approval window.

The reference issuer restricts permits to **one use**, **15 minutes maximum
validity**, and the harmless built-in `echo` or `add` tools. No wallet,
DEX, external URL, arbitrary shell or financial actions can be signed by
this CLI. An agent cannot change an approved parameter or audience.

## Operator procedure (Unix reference)

Install: `python -m pip install -e ".[crypto]"`.

1. Have an agent produce an **unsigned** JSON v2 permit draft using
   `PermitBuilder.build_unsigned_v2(key_id="issuer-key-1",
   audience="kernel-one")` and `permit_to_mapping`. Ensure the
   permitted `valid_from_ms` / `valid_until_ms` are real UTC
   milliseconds, not virtual-clock values.
2. The **human approver independently inspects the exact file**, including
   actor, scope, parameter values and destination kernel. On the approver's
   separate trusted machine, provision the Ed25519 signing PEM via a
   short-lived *preopened file descriptor*, not command-line text, a model
   prompt, an environment variable or git. The calling operator/secret manager
   is responsible for securely opening the FD.
3. Approver runs `shards-kernel issuer approve --draft draft.json
   --reviewer operator-one --key-fd 3 --out approval.json`. The CLI
   refuses a non-interactive console and requires the operator to enter
   `APPROVE <full-permit-id>`. The resulting approval is valid for
   at most five minutes and saved as a **new** mode-0600 file.
4. Transfer the unsigned draft + signed approval to the separately trusted
   issuer machine. Pin the approver public key **out of band**, not from the
   approval file. Securely provide a DIFFERENT issuer Ed25519 private key
   via another preopened FD.
5. Issuer runs:

```bash
shards-kernel issuer sign \
  --draft draft.json \
  --approval approval.json \
  --out signed-permit.json \
  --key-fd 3 \
  --approver-public-key-hex "<64 lowercase hex chars from trusted operator>" \
  --expected-issuer offline-issuer \
  --expected-key-id issuer-key-1
```

Neither the CLI nor the kernel automatically generates signing keys.
The operator must supply Ed25519 PKCS#8 PEM through FD 3 using a trusted
launcher or secret-manager pipe. Never use `--key-fd 0`, never publish
private material, and do not add any private-key parameter to the gateway.

The signed permit is serialized with `permit_to_mapping`, suitable for
the kernel's verified `permit_from_mapping` path; it is signed only after
the approval signature verifies against the independent approver key.

Output files are created exclusively (`O_EXCL`) with mode 0600; a
preexisting output is never overwritten. Failures use sanitised messages
and nonzero exit status.

## Safety and assurance limits

- The interactive check is an **operator UX gate**, not a trusted hardware
  human-presence attestation. A compromised approval machine could simulate
  terminal input.
- The issuer trusts the public approver key it was independently provisioned
  with. A malicious owner of BOTH signer keys can bypass separation; KMS/HSM
  roles, approval logs, MFA and remotely enforced signing policy are
  outstanding.
- The reference workflow provides no transactional approval-consumption
  store and does not prevent generating the same signed permit twice.
  Shards-Kernel's nonce registry prevents executing that exact permit a
  second time in its local audited runtime. Distributed atomic consumption
  remains unverified.
- No encrypted PKCS#8 password transport or cloud KMS adapter is provided;
  only a protected short-lived FD to the signer can supply unencrypted
  PKCS#8 material. Use a secret manager/HSM for production rather than
  maintaining PEM files.
- No runtime process isolation or endpoint identity is established merely
  by installing these CLI subcommands: enforce different hosts/UIDs and
  privileges during actual deployment.
- A successful reference demo does not authorise trading keys or remote
  MCP tool execution.

Remaining acceptance is tracked by
[production gateway #79](https://github.com/Shards-foundation/Shards-kernel/issues/79)
and [issuer lifecycle #68](https://github.com/Shards-foundation/Shards-kernel/issues/68).
