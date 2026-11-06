# Unattended operator automation

These scripts are read-only additions to the existing operator doctor, release gates,
SQLite restore drill and independently reviewed production-readiness programme.
They do not issue permits, invoke governed tools, modify the operator database,
self-repair, deploy, or declare production readiness.

Python 3.9+ on Linux, macOS and Windows. Structured JSON logging and explicit
nonzero exit codes allow cron, systemd or other supervisors to consume results.

## Operator health probe

~~~bash
python scripts/ops/probe_operator.py --url http://127.0.0.1:8765 --dry-run
python scripts/ops/probe_operator.py --url http://127.0.0.1:8765
python scripts/ops/probe_operator.py --check-status --expected-kernel-id operator-local
python scripts/ops/probe_operator.py --checks 0 --interval 30 --timeout 5 --attempts 3
~~~

Only explicit loopback HTTP(S) origins (127.0.0.1 or [::1], with a port) are
accepted. The probe never follows redirects or honors proxy environment
variables, bounds responses to 8 KiB, and uses timeouts and capped exponential
backoff for transient errors.

By default only the public GET /health is read. Optional --check-status reads
authenticated GET /status using SHARDS_KERNEL_API_KEY injected by the trusted
operator environment. The credential is never sent with the public health
request or written to logs. With --expected-kernel-id, a mismatched service
fails closed. --checks 0 watches continuously until an unhealthy response
or signal; it does not automatically restart a failed service.

A healthy response is **local process-status evidence only**. It does not
prove action authorisation, multi-host durability, revocation, audit-chain
integrity, ledger restoration or external effect reconciliation.

## Signed operator policy preflight

Requires the existing optional cryptography dependency:

~~~bash
python -m pip install -e '.[crypto]'
python scripts/ops/policy_preflight.py \
    --policy /srv/shards/operator-policy.json \
    --min-ttl-seconds 86400 \
    --minimum-revision 7 \
    --expected-kernel-id operator-local
~~~

The operator must inject SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX as the independently
pinned, lowercase 64-character Ed25519 **public** key. Private keys never
belong on the operator service host. This script invokes the **existing kernel
signed-policy verifier** instead of maintaining independent crypto code.
Signature, schema, file bounds and current validity are enforced by that verifier.
The script additionally checks a configurable minimum remaining lifetime,
revision floor and service identity; its output is redacted and machine-readable.

This check does **not** write the SQLite revision checkpoint. It therefore cannot
establish durable anti-rollback, detect a replaced database, or certify remote
ingress. The service must still perform its own checks under its exclusive lock.
The --minimum-revision argument is only an operator-provided floor.

## Exit status and operations

| Code | Meaning | Action |
| --- | --- | --- |
| 0 | Requested checks succeeded, or probe dry run validated | Continue other mandatory acceptance gates |
| 1 | Health probe failed | Investigate operator state, credentials, signed-policy expiry and logs |
| 2 | Invalid configuration, missing dependency, or signed-policy validation failure | Fix configuration or install the optional crypto dependency |
| 130/143 | SIGINT/SIGTERM received | Review logs and restart using the operator's service manager |

Negative-path test suite:

~~~bash
python -m pytest tests/test_ops_automation.py -q
~~~

Common failure boundaries: wrong system time can invalidate signed policies;
a database can be rolled back without a trusted external anchor; missing bearer
credentials make /status fail rather than downgrade to unauthenticated access;
and response redirects are refused so credentials cannot leak to another origin.
