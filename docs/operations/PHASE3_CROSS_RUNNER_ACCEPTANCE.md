# Phase 3 ephemeral cross-runner acceptance (NOT production certification)

## Architecture and scope

This workflow runs on **two independent GitHub-hosted Ubuntu runner jobs**. The
first VM generates an ephemeral Ed25519 private key and issues one signed
\`add(17,25)\` permit. It uploads only the proposal, signed permit, public key
and limited manifest. The second VM downloads the artifact, verifies the
public key against a separate job output, enrolls the verifier, checks
tampered-proposal denial, runs the harmless add once, checks replay denial
and verifies local audit evidence. It tests the **exact PyPI v0.1.3 wheel**
by SHA-256 on both jobs, in isolated virtualenvs outside the checkout.

The test checks distinct Linux boot IDs to detect accidental same-boot
execution. It does **not** establish tamper-proof host attestation or
genuine independently administered security principals. GitHub controls
both CI jobs, artifacts and workflow configuration.

**Critically, the issuer's \`APPROVE\` is mocked by test code.**
No real person approved the permit. This is an automated signed-permit
contract, *not* the production human-approval or protected-host gate.
Permit validity is five minutes; excessive GitHub queueing must fail
closed rather than extending the permit or disabling expiry.

## Run

Push to \`feat/dual-host-acceptance-20261112\`, or open a PR against its
parent \`feat/termux-v3-offline-issuer-20261108\`. Workflow:
\`.github/workflows/phase3-cross-runner-acceptance.yml\`.

Inspect the two job logs and download
\`phase3-cross-runner-evidence\`. Do **not** upload private keys,
real service credentials or customer data.

## What still must happen on real infrastructure

| Gate | Required independent evidence |
| --- | --- |
| Human approver | Human signs exact permit draft from separately protected identity; issuer verifies signature; replays and unapproved proposals denied |
| Persistent dual host | Dedicated issuer machine and agent/verifier machine with distinct OS users, independent secret managers and out-of-band pinned public keys |
| Physical Android | Actual Termux device outputs from signed build and real localhost Qwen plus transferred externally issued permit; no signer on phone |
| Shared permit state | Both deployed operator hosts race on a dedicated PostgreSQL primary; exactly one execution and one authority audit reservation across network failures |
| Provider reconciliation | Real non-financial provider with idempotency/read-back; unknown/partial outcomes quarantined until externally reconciled |
| mTLS ingress | Deployed authenticated public endpoint, pinned client/server certificates, identity revocation, rate and resource bounds |
| Integrity/operations | Separately administered signed audit-root anchor, immutable off-host backups, restore/crash/rotation/rollback/alert drills |
| Release governance | Exact wheel hash, SBOM/provenance, formal independent security review, protected CI and owner go/no-go |

These remain **BLOCKED / NOT VERIFIED** until produced. The cross-runner
job must not automatically unlock a PyPI release or merge.
