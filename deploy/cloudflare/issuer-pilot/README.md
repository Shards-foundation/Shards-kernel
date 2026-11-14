# Cloudflare isolated permit issuer pilot

**Status:** Deployed on Workers Free, **LOCKED**. This is an experimental,
approval-gated service, **not** a production signing authority or KMS/HSM.

## Where

- Account: `Ayais12210` (the separate, otherwise empty Cloudflare account).
- Script: `shards-permit-issuer-pilot`.
- D1: `shards-issuer-approval-ledger`, EU jurisdiction.
- Optional Workers.dev: `https://shards-permit-issuer-pilot.ayais12210.workers.dev`.
- Public preview URLs: **disabled**.
- 2026-11-14 deployment: **100% traffic by Cloudflare API**, confirmed via
  `GET /workers/scripts/{script_name}/deployments`.
- Public HTTPS verification: the **previous** deployed revision passed GitHub-hosted
  CI on 2026-11-14 (GET /health 200, /v1/status LOCKED, POST /v1/issue 503).
  **Current deployed revision: NOT REVERIFIED** after the liveness-only change.
  The manual `issuer-pilot-live.yml` workflow must be run and recorded.
  These live results are not evidence for PR source correctness.

## Deployment safety defaults

- `GET /health` is public liveness-only. `GET /v1/status` reports LOCKED publicly only while unprovisioned; **once provisioned, it requires the caller bearer**. Authenticated status crypto probes are cached for at most 15 seconds per isolate (concurrent requests share one probe). Issuance always rechecks signing keys independently; cached status never authorises any permit.
- `POST /v1/issue` returns HTTP **503 LOCKED** until all custody bindings
  are supplied. **No private key or bearer token was provisioned**.
- Unrecognised routes: 404. Unexpected methods on issue: 405.
- Required secret inputs for a future controlled activation:
  `APPROVER_PUBLIC_KEY_HEX` (pinned offline human approval key),
  `ISSUER_PRIVATE_KEY_PKCS8_B64` (a distinct private Ed25519 key in a
  Cloudflare secret), `ISSUER_PUBLIC_KEY_HEX`, `ISSUANCE_ACCESS_TOKEN`,
  `ISSUER_NAME`, `ISSUER_KEY_ID`, `ISSUER_AUDIENCE`.
  D1 binding `ISSUANCE_DB` must also exist.
- Authorised `echo` and `add` only, one execution maximum, <= 15-minute
  permit window, <= 10-minute independent signed approval.
- Operator approval format: `shards.operator-approval.v1`; permit wire
  format: Shards Kernel Ed25519 v2. Verify canonical format independently
  against **the exact installed Shards Kernel release** before activation.
- Signed approval, exact draft hash, permit id and audience are verified
  *before* signing. Issuer signature is checked against independently pinned
  issuer public key. D1 uniqueness prevents duplicate issue/approval use.
- Errors and D1 outages never return an executable signed permit.
- This is a **cross-host protocol pilot only**: Worker secrets can be
  changed/exfiltrated by sufficiently privileged Cloudflare administrators.
  A Cloudflare Worker secret is **not** a hardware-attested private key or a
  defence against the account owner. On 2026-11-14 the Cloudflare MCP OAuth
  connection was restricted to Shards-inc only; issuer-account API access
  returned HTTP 403. The separate Cloudflare Access application's
  all-account grant remains unclassified. **Do not activate the signer until
  all administrative paths and independent approver custody are verified.**

## D1 ledger

```sql
CREATE TABLE IF NOT EXISTS issued_permits (
  permit_id TEXT PRIMARY KEY,
  approval_digest TEXT NOT NULL UNIQUE,
  issued_at_ms INTEGER NOT NULL,
  subject TEXT NOT NULL,
  audience TEXT NOT NULL,
  action TEXT NOT NULL,
  valid_until_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS issued_permits_issued_at_idx
  ON issued_permits (issued_at_ms);
```

The D1 row is a durable issuance record, **not** a trusted Kernel execution
receipt. Kernel must independently persist its own audit and replay ledger.
Worker issuance is at-most-once; if response is lost, approval is consumed,
and recovery requires a **new independent approval**, never an automatic retry.

## Validation

```sh
node --test tests/cloudflare-issuer-pilot/test_worker.mjs
```

The GitHub-hosted Node security suite must pass on the exact reviewed commit;
the test count is tracked by the workflow rather than frozen in this document.
The Python 3.13 CI gate installs exactly
`shards-kernel[crypto]==0.1.4` and checks the complete Python approver →
JavaScript issuer → Python Kernel verifier round-trip using ephemeral keys.
This interop gate must pass before activation.

## Remaining security gates

1. Review source and tests independently; confirm operator policy and permit
   canonical bytes match the exact Kernel binary.
2. Establish an **offline human approver** key on a separate trusted device;
   pin its public key, never send its private key to the Worker.
3. Restrict Cloudflare administrator/service-token access so the agent and
   AI-managed OAuth connector cannot change the signing Worker or its secrets.
4. Provision distinct issuer Ed25519 key under a protected secret management
   process. Cloudflare Worker secrets alone do not meet hardware-key custody.
5. Configure Access for operator initiation, check approval flow, and complete
   negative/positive and crash/replay E2E across separate hosts. Never allow
   automatic agent approval or an unattended signing endpoint.
6. Confirm billing remains on Workers Free. Exceeding a Free resource quota
   must cause DENY/unavailability rather than billing or authority bypass.

No new paid resources, payment methods or upgrades are required for this
**LOCKED** pilot. No production keys, permits or endpoints were activated.
