.PHONY: sync format lint typecheck test test-fast bc cov codegen unasync check build clean

# Install the project and the dev dependency group into a uv-managed venv.
sync:
	uv sync

format:
	uv run ruff format src tests
	uv run ruff check --select I --fix src tests

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

typecheck:
	uv run mypy
	uv run basedpyright

# Full suite, parallelized across cores (xdist). Legacy-compat/BC tests included.
test:
	uv run pytest -n auto

# Serial run (easier debugging / accurate tracebacks).
test-fast:
	uv run pytest

# Backward-compatibility oracle only.
bc:
	uv run pytest tests/bc -n auto

cov:
	uv run coverage erase
	uv run pytest -n auto --cov=vulners --cov-branch --cov-report=term-missing

# Regenerate sync resources from the async source of truth and check drift.
unasync:
	uv run unasyncd

# Regenerate all codegen artifacts and fail on drift (CI gate G4).
codegen:
	uv run python -m codegen.check

check: lint typecheck test

build:
	uv build

clean:
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
