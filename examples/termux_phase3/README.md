# Shards Termux Qwen3 — Phase 3 offline issuer pilot

**Status:** review-only offline signer + phone verifier. Not a deployed issuer, production sandbox, remote gateway or authenticated web service.

This is a deliberately limited design: a separate, human-operated device signs exact Ed25519 permits and copies only the resulting public key and signed permit to the phone. The phone never needs the private v3 issuer key. It uses `StrictKernel` 0.1.3 and the existing Phase 2 `agent_v2.py` **only for tool implementations and model JSON proposals**, not for permit issuance.

## Key trust boundaries

- Operator host: `operator_issuer.py` + `phase3_protocol.py`; private key stays here. Install `shards-kernel[crypto]==0.1.3`.
- Android Termux: `agent_verifier_v3.py`, `phase3_protocol.py` and its already-working `agent_v2.py`. Install `shards-kernel[crypto]==0.1.3`. Use `127.0.0.1:8080` llama.cpp for `ask` only.
- Only `echo`, `add`, `list_notes`, `read_note`, `remember`, and `recall` can execute. Each permit covers one action and exact JSON parameters. No shell, repository writes, external network actions or autonomous authority.
- No HTTP signing endpoint. The issuer requires a local terminal operator typing `APPROVE` for every proposal. Never give its private key to Termux or an AI agent.
- **No real isolation until the issuer actually runs under a different host/OS security principal.** Same-UID simulated testing is not isolation. Kernel is not an OS sandbox.

## A. Protected operator host

Download/copy the two operator-side files, create a restricted directory, install Python dependencies, then:

```bash
python -m pip install 'shards-kernel[crypto]==0.1.3'
python operator_issuer.py init
python operator_issuer.py public
```

Record `PUBLIC_KEY_HEX` and `PUBLIC_KEY_SHA256` through an independently authenticated channel. The operator **must not** export `issuer-private.key` or share this key with the phone. Protect the host and its user account.

## B. Termux — non-destructive enrolment

Do not remove or rename your working Phase 2 installation. Place the two Android-side files next to `~/shards-local-ai/agent_v2.py` and run:

```bash
cd ~/shards-local-ai
python agent_verifier_v3.py status
python agent_verifier_v3.py enroll '<PUBLIC_KEY_HEX>' '<PUBLIC_KEY_SHA256>'
python agent_verifier_v3.py propose add '{"a":17,"b":25}'
```

The last command prints a `~/.shards-qwen3-v3/proposal-<id>.json` path. Copy that file to the operator device **as data** (e.g. a secure file transfer), inspect and sign it there:

```bash
python operator_issuer.py issue /path/to/proposal.json /path/to/permit.json
```

`APPROVE` is typed *on the protected operator host*, not in the Android agent. Bring `permit.json` back to Termux. Within the permit's short validity window, use:

```bash
python agent_verifier_v3.py execute /absolute/path/proposal.json /absolute/path/permit.json
python agent_verifier_v3.py audit
```

Expected on a valid one-time signed add: `DECISION: ALLOW`, `RESULT: 42`, and `AUDIT: PASS`. Reuse/expiry/tampering should yield `DENY` or `FAIL CLOSED`.

The optional Qwen3 proposal route is:

```bash
python agent_verifier_v3.py ask 'Add 17 and 25'
```

This produces unsigned proposals only; it **does not issue or execute permits automatically**.

## Continuity and cutover

Phase 3 uses a distinct kernel ID and `~/.shards-qwen3-v3/audit-v3.sqlite3`. It does **not** touch your old `~/.shards-qwen3-v2/audit.sqlite3`, old `operator.key`, or old memory. V2 history stays independently verifiable with `python agent_v2.py audit`. New V3 memory starts empty; deliberate import could be added after validation. Never run an unreviewed delete or migrate action on the old DB.

Phase 2 can still issue local permits for its **own** v2 kernel while the old key exists; it cannot sign valid permits for the v3 audience/key ID. Once v3 live acceptance is complete, plan explicit removal of the *legacy* key from the Android phone, and separately address the fact that local code and data remain writable to a compromised Termux UID. Do not confuse removing that key with an OS sandbox.

The proposal envelope expires after fifteen minutes. On expiry, generate a new proposal; signed permits expire five minutes after approval. Avoid transferring private keys, and verify the public-key fingerprint out of band before enrolment. Human approvals are required per action.

## Test boundary

`python -m unittest -v test_phase3.py` tests protocol validation only, without any local inference or kernel installation. Compile with `python -m py_compile *.py`. A full E2E test **requires a protected issuer host and your real Termux**; offline unit tests are not evidence of that deployment.
