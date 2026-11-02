# Offline permit and audit acceptance demonstration

Run from a source checkout or installed wheel with the optional maintained
Ed25519 cryptography dependency:

```bash
python -m pip install -e ".[crypto]"
shards-kernel demo
shards-kernel demo --json
```

The command is **non-financial** and deterministic. It uses a real Ed25519
signature on a narrow `echo(text="approved")` permit. The kernel verifier
holds only the public key. It records explicit PASS/FAIL results for seven
separate acceptance gates:

| Gate | Expected |
|---|---|
| Missing signed permit | DENY |
| Valid, issuer-bound, audience-bound permit | ALLOW once, returning approved text |
| Same signed permit again | DENY — replay |
| Changed execution parameters | DENY — scope mismatch |
| Expired but correctly signed permit | DENY — expired |
| Revoked public issuer key | DENY — revoked |
| Fresh kernel restores verified evidence | DENY — previous permit still consumed |

The demo exits `0` only when **all** conditions hold; otherwise it exits
`2`. In `--json` mode it reports each gate, an audit root hash, the number
of audited entries and an explicit `production_ready: false`.

## Deliberate security scope

**This is a test harness, not an operational gateway or issuer deployment.**
To ensure a zero-configuration reproducible demonstration, the issuer creates
an ephemeral private key *inside the demonstration process*, and the kernel
uses `VirtualClock(1000)`. Neither is suitable for a production service.
The key is not returned or logged; the kernel receives only the public key.

The scenario restores a verified **in-memory evidence bundle** into a new
kernel instance and asserts replay protection reconstruction. It does not
demonstrate a disk crash, a live remote agent, TLS, independently deployed
issuer, cross-replica transactional nonce consumption, multi-tenant isolation,
or durable revocation distribution. Those gates remain open under issues
[#69](https://github.com/Shards-foundation/Shards-kernel/issues/69),
[#68](https://github.com/Shards-foundation/Shards-kernel/issues/68) and
[#63](https://github.com/Shards-foundation/Shards-kernel/issues/63).

## Tests

```bash
python -m pytest tests/test_operator_demo.py -q
```

This confirms the command's fail-closed behaviour, stdout secret redaction,
and reproducibility. Use the official MCP SDK interoperability tests in
`tests/test_mcp_sdk_v2.py` for the local MCP transport layer; those are
separate tests, not implied by the offline CLI demo.
