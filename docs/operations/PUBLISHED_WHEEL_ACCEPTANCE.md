# Published Shards-Kernel wheel: reproducible acceptance baseline

**Scope:** `shards-kernel==0.1.3`, **not** current `main`, not a claim of
production readiness. The immutable release tag is pinned to commit
`5f122099d37c241b5388e10ca2b2d65f74840d47`.

## Why the separate gate exists

The existing CI uses an editable source install, so its tests cannot prove
that a user receives the same behaviour from the published PyPI artifact.
The published wheel SHA-256 is pinned to
`baf246e771ceb559d007efafbe8ba66099bd8a65d488ca60294cae5313278df9`
and is checked **before installation**. The harness source is taken from the
checked-out Git commit and independently recorded in the evidence manifest;
the two tagged test modules are extracted from the immutable v0.1.3 commit.
The workflow also runs negative-path unit tests for the evidence reporter.
The `published-v0.1.3-acceptance.yml` workflow downloads **only the wheel**,
installs that wheel in the runner, then copies the test harness into an
isolated temporary directory outside the Git checkout. It executes:

1. Seven published offline CLI demo checks and strict variant runtime tests.
2. SQLite recovery, changed-entry detection, and the known truncation
   limitation using a separately retained **test-only** root.
3. Five rounds of 20 competing threads for a single-use permit.
4. Five rounds of independent operating-system processes competing for one
   signed Ed25519 permit through shared PostgreSQL authority.
5. Three abrupt process-exit rounds after `RESERVED` and three after
   `DISPATCHED`; verifies quarantine and budget preservation.
6. Two exact tagged PostgreSQL integration modules from v0.1.3, not tests
   accidentally fetched from `main`.

The workflow **requires** an explicitly opted-in disposable PostgreSQL primary,
whose DSN must identify a local-only socket or loopback connection and a
recognised test database name. The staged `conftest.py` performs this check
**before** pytest collects *any* tagged or new test module, preventing
accidental writes to unapproved databases. It fails if the exact 41 test
identities (including both crash parametrisations) do not match, a test
fails or skips, or the pytest process exits nonzero. No secrets or
live downstream services are used. The result is a GitHub Actions artifact
containing the downloaded wheel, JUnit output, console log,
`acceptance-sources.json`, harness commit, pytest exit code,
resolved dependency versions and `acceptance.json` with the
**expected-versus-actual** wheel SHA-256, exact test identities, staged source
hashes, PostgreSQL server version and UTC run timestamp.
A missing wheel, failed setup or missing JUnit generates a machine-readable
`FAIL` receipt rather than silently omitting evidence. This record is test
**evidence**, not a signed attestation or a production certificate.

### Review and release rules

- GitHub Actions status is authoritative only for the specific wheel hash,
  test suite and environment it reports.
- Updating `main` does **not** update PyPI v0.1.3. This is a frozen
  historical regression baseline; update the pinned version, release commit,
  and checks in a separately reviewed release acceptance PR for future tags.
- CI passing is not proof of independent external review, two-host operation,
  multi-region failover, an off-host signed checkpoint, operational certificate
  rotation, external-provider reconciliation, or exactly-once side effects.
- This workflow must never introduce a model-facing `initialize_schema`,
  credentialed production endpoint or a fallback to local permit accounting.
- Do not post production DSNs, private issuer keys, bearer tokens or signed
  live permit contents into workflow logs or documentation.

## Android/Termux field observations (not automated CI evidence)

An operator reported execution on Android Termux with Python 3.13,
`shards-kernel==0.1.3`, PostgreSQL 18.2, and an Android-compatible
cryptography 48.0.1 build. Reported results included: offline demo 7/7,
33 PostgreSQL integration tests, five 20-thread rounds, five two-process
rounds, three reserve-crash rounds, three dispatch-crash rounds, plus
SQLite recovery and data-tamper checks. These are **operator-supplied
terminal screenshots**, not cryptographically verifiable CI logs.

For reproducibility, the CI harness above independently reruns the relevant
checks. The operator screenshots alone do not certify real multi-host
recovery or off-host audit anchoring. The Termux `[crypto]` pip install may
attempt a Rust build of `cryptography`; install an Android-compatible
Termux package first if required. The Linux CI wheel installation must
never be represented as proof of Android binary compatibility.
