# Termux Qwen3 → Shards-kernel 0.1.3: governed local agent (v2 pilot)

This is an experimental *same-user* Android integration. It is NOT an OS sandbox, an externally isolated signing service, or an autonomous production agent. Qwen3 has no direct access to arbitrary filesystem paths, subprocesses, network destinations, wallet actions, or deployment tools through this script. An untrusted model proposes JSON; the operator manually reviews every step before an exact one-use Ed25519 permit is issued and verified by StrictKernel.

## Requirements

- Python 3.11+ in Termux; this example was developed for Python 3.13.
- `shards-kernel==0.1.3` and `python-cryptography` (`cryptography`) installed.
- Optionally a local Qwen3 GGUF model served by `llama-server` at `http://127.0.0.1:8080`.

## Install without ChatGPT attachments

Use an immutable, commit-pinned source URL for this pilot. It remains valid after the review branch is deleted. Inspect the file before execution; use a tagged release once this example is published:

```sh
mkdir -p ~/shards-local-ai && cd ~/shards-local-ai
curl -fL --retry 3 --connect-timeout 15 -o agent_v2.py \
  https://raw.githubusercontent.com/Shards-foundation/Shards-kernel/bd44a3e19a8a21bafbb9c62c1d83872cb7c49b25/examples/13_termux_qwen3_governed_agent.py
python -m py_compile agent_v2.py
python agent_v2.py self-test
python agent_v2.py init
```

The pinned commit is an immutable review artifact, not a published release or production certification. Review `agent_v2.py` before running it.

## Try deterministic tools without the LLM

```sh
python agent_v2.py run add '{"a":17,"b":25}'
```

Review and type `APPROVE` at the Python prompt (not the shell prompt). The expected result after confirmation is `DECISION: ALLOW`, `RESULT: 42` and `AUDIT: PASS`.

Create a harmless note for the read-only workspace:

```sh
printf 'This is my local governed workspace.\n' > ~/.shards-qwen3-v2/workspace/hello.md
python agent_v2.py run read_note '{"name":"hello.md"}'
python agent_v2.py run remember '{"key":"demo","value":"Qwen3 is local"}'
python agent_v2.py run recall '{"key":"demo"}'
python agent_v2.py audit
```

Every `run` call asks for a separate approval and creates its own one-use permit. Notes are constrained to files within `~/.shards-qwen3-v2/workspace/` with `.txt`, `.md` or `.json` extensions. Hidden, nested, symlink and oversized (over 8 KiB) files are refused. This is an application-level restriction, not a strong filesystem sandbox.

## Try Qwen3 natural-language proposals

Keep your `llama-server` running in another Termux session on `127.0.0.1:8080` and run:

```sh
python -u agent_v2.py ask 'Add 17 and 25'
python -u agent_v2.py ask 'Remember the value "test passed" under key demo, then recall demo'
```

The small local model may occasionally produce invalid JSON. The bridge fails closed rather than trying to recover unsafe malformed actions. No unattended execution is enabled; each of up to three steps requires fresh `APPROVE` input.

## Isolation and recovery limitations

1. **The model and issuer are not security-isolated.** The Python process reads the local signing key only after approval, but both operate under the same Android Termux Unix UID. Any malicious code running as that UID could access it. For a trustworthy split, move the private key to an independent operator account, device, hardware signer, or secured service with authenticated approval and public-key verification on the Termux agent host.
2. **There is no OS-level sandbox.** The allowed registry and prompt are not a substitute for process isolation. Only trusted tool handlers should be registered.
3. **Memory updates and kernel audit are not one atomic external-effect transaction.** Unexpected termination during a write may require reconciliation. Do not claim universal exactly-once execution.
4. **A valid local hash chain proves internal consistency, not external provenance.** Use an independently held root hash/signature for tamper-evidence against an operator with database access.
5. **Not a public API.** The `llama-server` should bind only to `127.0.0.1`.
6. **Do not store secrets in model memory or notes.** Model-visible tool arguments may be audited.

The pilot deliberately uses a NEW state directory `~/.shards-qwen3-v2/`. It does not alter `~/.shards-qwen3/` or the existing `bridge.py` state. If the operator key is lost, old permits and identity are not recoverable by auto-generating a new key; there is no silent key rotation.

## Acceptance gate

- Local static tests cover schema parsing, unknown/oversized arguments, path traversal, symlinks, note byte limits, SQLite memory, and signing-key permissions.
- Run `python agent_v2.py self-test` on a real Termux installation to test signed `ALLOW`, missing-permit `DENY`, replay `DENY`, mismatched-parameter `DENY`, note read, memory persistence, SQLite audit restart and verification.
- No production-readiness claim is made until issuer/process isolation and external audit anchoring are implemented and independently tested.