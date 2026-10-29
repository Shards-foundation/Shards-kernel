# Contributing to kernels

We love your input! We want to make contributing to this project as easy and transparent as possible.

## Pull requests

1. Fork the repo and create your branch from `main`.
2. Add tests for new behaviour, edge cases, failure paths, and security-sensitive changes.
3. Run the full test suite and coverage gates before opening a pull request.
4. Include the test evidence and any known limitations in the pull request description.

## Required local verification

Install the development dependencies, then run:

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest --cov=kernels --cov=implementations --cov-branch --cov-report=term-missing --cov-report=xml --cov-report=json:coverage.json --cov-fail-under=90
python scripts/ci/check_governance_coverage.py coverage.json
python scripts/ci/smoke.py
python examples/01_minimal_request.py
python examples/02_verify_evidence.py
python examples/03_fail_closed_ambiguity.py
python examples/04_sqlite_persistent_ledger.py
```

The overall line-coverage gate is **90% minimum** and the governance-specific branch-coverage gate must also pass. CI verifies the supported Python matrix, package build/import, demos, static security scans, dependency auditing, and documentation build. Do not lower coverage thresholds to make a failing change pass; add tests or document an explicitly reviewed exclusion instead.
