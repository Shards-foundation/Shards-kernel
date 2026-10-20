PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: install install-dev lint format format-check typecheck test test-cov security dep-scan smoke build ci clean

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"
	$(PIP) install build

lint:
	ruff check . --select E,F --ignore E501

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy kernels implementations

test:
	pytest

test-cov:
	pytest --cov=kernels --cov=implementations --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=48
	$(PYTHON) scripts/ci/check_governance_coverage.py coverage.json

security:
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -r kernels implementations -q; \
	else \
		echo "bandit not installed; skipping security scan"; \
	fi

dep-scan:
	safety check --full-report || true
	pip-audit

smoke:
	./scripts/smoke.sh

build:
	@if $(PYTHON) -c "import build" >/dev/null 2>&1; then \
		$(PYTHON) -m build; \
	else \
		echo "python-build package not installed; skipping build step"; \
	fi

twine-check:
	twine check dist/*

ci: lint test-cov smoke build

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info .tmp
