# Pipeline Gates

**Version:** 0.1.0  
**Classification:** CI/CD  
**Last Updated:** January 2025

---

## 1. Overview

Pipeline gates are checkpoints that code must pass before progressing through the development lifecycle. Each gate enforces specific quality, security, and compliance requirements.

---

## 2. Gate Definitions

### 2.1 Gate Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DEVELOPMENT                                   │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐             │
│  │  Code   │───▶│  Lint   │───▶│  Test   │───▶│ Security│             │
│  │  Write  │    │  Gate   │    │  Gate   │    │  Gate   │             │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           INTEGRATION                                   │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐             │
│  │  Build  │───▶│  Int.   │───▶│ Perf.   │───▶│ Review  │             │
│  │  Gate   │    │  Test   │    │  Gate   │    │  Gate   │             │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           RELEASE                                       │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐             │
│  │ Staging │───▶│ Smoke   │───▶│ Approval│───▶│ Deploy  │             │
│  │  Gate   │    │  Gate   │    │  Gate   │    │  Gate   │             │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Development Gates

### 3.1 Lint Gate (G-LINT)

**Purpose:** Ensure code style and quality standards.

| Check | Tool | Threshold |
|-------|------|-----------|
| Python style | ruff/flake8 | 0 errors |
| Type hints | mypy | 0 errors |
| Import order | isort | 0 errors |
| Formatting | black | 0 diffs |
| Docstrings | pydocstyle | 0 errors |

**Configuration:**

```yaml
# pyproject.toml
[tool.ruff]
line-length = 88
select = ["E", "F", "W", "I", "N", "D"]

[tool.mypy]
python_version = "3.11"
strict = true

[tool.black]
line-length = 88
target-version = ["py311"]
```

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_lint.sh

set -e

echo "Running lint gate..."

echo "[1/4] Running ruff..."
ruff check shards_kernel/ tests/

echo "[2/4] Running mypy..."
mypy shards_kernel/

echo "[3/4] Running black..."
black --check shards_kernel/ tests/

echo "[4/4] Running isort..."
isort --check-only shards_kernel/ tests/

echo "Lint gate passed."
```

### 3.2 Test Gate (G-TEST)

**Purpose:** Ensure code correctness through automated testing.

| Check | Tool | Threshold |
|-------|------|-----------|
| Unit tests | unittest | 100% pass |
| Coverage | coverage | >80% |
| Invariants | custom | 100% pass |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_test.sh

set -e

echo "Running test gate..."

echo "[1/3] Running unit tests..."
python -m unittest discover -s tests -v

echo "[2/3] Running coverage..."
coverage run -m unittest discover -s tests
coverage report --fail-under=80

echo "[3/3] Running invariant tests..."
python -m pytest tests/test_invariants.py -v

echo "Test gate passed."
```

### 3.3 Security Gate (G-SEC)

**Purpose:** Identify security vulnerabilities.

| Check | Tool | Threshold |
|-------|------|-----------|
| Static analysis | bandit | 0 high/critical |
| Dependency audit | safety | 0 vulnerabilities |
| Secrets scan | detect-secrets | 0 findings |
| SAST | semgrep | 0 high/critical |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_security.sh

set -e

echo "Running security gate..."

echo "[1/4] Running bandit..."
bandit -r shards_kernel/ -ll

echo "[2/4] Running safety..."
safety check

echo "[3/4] Running detect-secrets..."
detect-secrets scan --all-files

echo "[4/4] Running semgrep..."
semgrep --config=auto shards_kernel/

echo "Security gate passed."
```

---

## 4. Integration Gates

### 4.1 Build Gate (G-BUILD)

**Purpose:** Ensure package builds correctly.

| Check | Tool | Threshold |
|-------|------|-----------|
| Package build | pip | Success |
| Wheel creation | build | Success |
| Import test | python | Success |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_build.sh

set -e

echo "Running build gate..."

echo "[1/3] Building package..."
pip install build
python -m build

echo "[2/3] Installing wheel..."
pip install dist/*.whl

echo "[3/3] Testing import..."
python -c "import shards_kernel; print(shards_kernel.__version__)"

echo "Build gate passed."
```

### 4.2 Integration Test Gate (G-INT)

**Purpose:** Verify component interactions.

| Check | Tool | Threshold |
|-------|------|-----------|
| Integration tests | pytest | 100% pass |
| Example execution | python | All pass |
| CLI tests | pytest | 100% pass |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_integration.sh

set -e

echo "Running integration gate..."

echo "[1/3] Running integration tests..."
pytest tests/integration/ -v

echo "[2/3] Running examples..."
for f in examples/*.py; do
    echo "Running $f..."
    python "$f"
done

echo "[3/3] Running CLI tests..."
python -m shards_kernel info
python -m shards_kernel --version

echo "Integration gate passed."
```

### 4.3 Performance Gate (G-PERF)

**Purpose:** Ensure performance requirements are met.

| Check | Tool | Threshold |
|-------|------|-----------|
| Decision latency | pytest-benchmark | <10ms p99 |
| Memory usage | memory_profiler | <100MB |
| Throughput | locust | >1000 req/s |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_performance.sh

set -e

echo "Running performance gate..."

echo "[1/3] Running benchmarks..."
pytest tests/benchmarks/ --benchmark-only

echo "[2/3] Checking memory..."
python -m memory_profiler tests/memory_test.py

echo "[3/3] Running load test..."
locust -f tests/load_test.py --headless -u 100 -r 10 -t 60s

echo "Performance gate passed."
```

### 4.4 Review Gate (G-REVIEW)

**Purpose:** Ensure human review of changes.

| Check | Requirement | Threshold |
|-------|-------------|-----------|
| Code review | GitHub | 1+ approval |
| Security review | Manual | For security changes |
| Architecture review | Manual | For arch changes |

---

## 5. Release Gates

### 5.1 Staging Gate (G-STAGE)

**Purpose:** Validate in staging environment.

| Check | Tool | Threshold |
|-------|------|-----------|
| Deployment | Kubernetes | Success |
| Health check | curl | 200 OK |
| Smoke test | pytest | 100% pass |

### 5.2 Smoke Gate (G-SMOKE)

**Purpose:** Quick validation of critical paths.

| Check | Tool | Threshold |
|-------|------|-----------|
| Boot test | python | Success |
| Request test | python | ALLOW |
| Audit test | python | Valid chain |
| Halt test | python | HALTED |

**Gate Script:**

```bash
#!/bin/bash
# scripts/gate_smoke.sh

set -e

echo "Running smoke gate..."

./scripts/smoke.sh

echo "Smoke gate passed."
```

### 5.3 Approval Gate (G-APPROVE)

**Purpose:** Human approval for release.

| Check | Requirement | Threshold |
|-------|-------------|-----------|
| Release approval | Manual | 1+ maintainer |
| Changelog reviewed | Manual | Complete |
| Version bumped | Automated | Correct |

### 5.4 Deploy Gate (G-DEPLOY)

**Purpose:** Final deployment checks.

| Check | Tool | Threshold |
|-------|------|-----------|
| Tag created | git | Exists |
| Package published | PyPI | Success |
| Docs published | ReadTheDocs | Success |

---

## 6. Gate Matrix

### 6.1 By Change Type

| Change Type | G-LINT | G-TEST | G-SEC | G-BUILD | G-INT | G-PERF | G-REVIEW |
|-------------|--------|--------|-------|---------|-------|--------|----------|
| Bug fix | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ |
| Feature | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Security | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅✅ |
| Performance | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Documentation | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ✅ |
| Dependencies | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ |

Legend: ✅ Required, ⚪ Optional, ✅✅ Enhanced

### 6.2 By Branch

| Branch | Gates Required |
|--------|----------------|
| feature/* | G-LINT, G-TEST |
| develop | G-LINT, G-TEST, G-SEC, G-BUILD |
| main | All gates |
| release/* | All gates + G-APPROVE |

---

## 7. Gate Failure Handling

### 7.1 Failure Response

| Gate | Failure Action |
|------|----------------|
| G-LINT | Block merge, fix required |
| G-TEST | Block merge, fix required |
| G-SEC | Block merge, security review |
| G-BUILD | Block merge, fix required |
| G-INT | Block merge, fix required |
| G-PERF | Warning, review required |
| G-REVIEW | Block merge, approval required |
| G-SMOKE | Block release, fix required |
| G-APPROVE | Block release, approval required |

### 7.2 Override Process

| Override Type | Requirement |
|---------------|-------------|
| Temporary bypass | 2 maintainer approvals |
| Permanent exception | Architecture review |
| Emergency release | CTO approval |

---

## 8. CI/CD Configuration

### 8.1 GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ruff mypy black isort
      - run: ./scripts/gate_lint.sh

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: ./scripts/gate_test.sh

  security:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install bandit safety
      - run: ./scripts/gate_security.sh

  build:
    runs-on: ubuntu-latest
    needs: [test, security]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: ./scripts/gate_build.sh

  integration:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: ./scripts/gate_integration.sh
```

### 8.2 Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.0
    hooks:
      - id: ruff
        args: [--fix]

  - repo: https://github.com/psf/black
    rev: 23.9.1
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
```

---

## 9. Metrics and Reporting

### 9.1 Gate Metrics

| Metric | Description |
|--------|-------------|
| Gate pass rate | % of builds passing each gate |
| Gate duration | Time to complete each gate |
| Failure rate | % of builds failing each gate |
| MTTR | Mean time to resolve gate failures |

### 9.2 Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│                    GATE STATUS DASHBOARD                    │
├─────────────────────────────────────────────────────────────┤
│ Gate      │ Last Run │ Status │ Duration │ Pass Rate      │
├───────────┼──────────┼────────┼──────────┼────────────────┤
│ G-LINT    │ 2m ago   │ ✅     │ 45s      │ 98.5%          │
│ G-TEST    │ 2m ago   │ ✅     │ 2m 15s   │ 99.2%          │
│ G-SEC     │ 2m ago   │ ✅     │ 1m 30s   │ 99.8%          │
│ G-BUILD   │ 2m ago   │ ✅     │ 1m 45s   │ 99.5%          │
│ G-INT     │ 2m ago   │ ✅     │ 3m 20s   │ 97.8%          │
│ G-PERF    │ 1d ago   │ ✅     │ 5m 10s   │ 95.2%          │
│ G-SMOKE   │ 1d ago   │ ✅     │ 30s      │ 99.9%          │
└─────────────────────────────────────────────────────────────┘
```
