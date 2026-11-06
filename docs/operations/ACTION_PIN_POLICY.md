# GitHub Actions immutable dependency policy

The repository requires third-party `uses:` references to be pinned to a
**full immutable Git commit SHA** or a container SHA-256 digest. Relative,
repository-owned `./` actions may remain local.

## Verified upstream release provenance (6 November 2026)

| Action repository | Release tag | Pinned commit (40 hex digits) | Steps |
| --- | --- | --- | --- |
| `github/codeql-action` | `v4.39.3` | `33d7b85da1a04171e211befe2c739303b9a4c066` | init, analyze, autobuild |
| `actions/jekyll-build-pages` | `v1.0.13` | `44a6e6beabd48582f863aeeb6cb2151cc1716697` | build |

Both refs were resolved from the official upstream GitHub repository tags,
not inferred from short hashes. The CodeQL tags `v4` and `v4.39.3`
were annotated tags pointing to the same commit on the verification date.
The Jekyll tags `v1` and `v1.0.13` pointed directly to the same
commit.

**Maintenance obligation:** SHA pinning is only a supply-chain immutability
control; it does not imply a dependency is secure indefinitely. Keep
GitHub Actions Dependabot enabled with weekly reviews and update the pinned
commit when a verified upstream release is issued. Never suppress a known
vulnerability by indefinitely holding an obsolete hash.

## CI enforcement

`tests/test_workflow_action_pins.py` checks every workflow in
`.github/workflows`, rejects floating remote refs, and asserts that
all CodeQL and Jekyll steps resolve to the verified release commits above.
An upstream source repository moving its major-version tag will not silently
change the code run by existing Shards-Kernel workflows.

Example:

```bash
python -m pytest tests/test_workflow_action_pins.py -q
```

All applicable CodeQL security scans, Pages build workflows, the full
Python CI matrix and the mandatory E2E gate must pass on the exact
pull-request head. Do not automatically merge dependency-bump PRs without
independent review and acceptance checks.

## Scope

No publishing credentials, kernel permit logic, service runtime, PyPI
release steps or repository branch protections are changed by this pinning
operation. A passing pin check proves only local workflow source policy,
not the upstream provenance of every package downloaded by each action.
