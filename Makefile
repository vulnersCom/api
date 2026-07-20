.PHONY: sync format lint typecheck test test-fast bc cov codegen unasync unasync-check check build clean

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

# Branch-coverage gate for the NEW v4 core (must stay at 100%; enforced by
# fail_under=100 in [tool.coverage.report]). The legacy v3 layer (base.py /
# vscanner.py / vulners/**) is covered by the v3 suite separately and is out of
# this gate's scope, so it is not listed among the measured modules below.
COV_MODULES = \
	--cov=vulners._base_client --cov=vulners._client --cov=vulners._config \
	--cov=vulners._exceptions --cov=vulners._logging \
	--cov=vulners._models --cov=vulners._pagination --cov=vulners._ratelimit \
	--cov=vulners._ratelimit_async --cov=vulners._resources --cov=vulners._response \
	--cov=vulners._retry --cov=vulners._streaming --cov=vulners._transport \
	--cov=vulners._transport_client_async --cov=vulners._transport_client_sync \
	--cov=vulners._types

cov:
	uv run coverage erase
	uv run pytest -n auto $(COV_MODULES) --cov-branch --cov-report=term-missing

# Full-package coverage (v4 core + legacy v3), informational only — not gated.
cov-all:
	uv run coverage erase
	uv run pytest -n auto --cov=vulners --cov-branch --cov-report=term-missing --cov-fail-under=0

# Regenerate the sync mirror (_ratelimit.py + resources/_sync + transport client)
# from the async source. `--extra fast` pulls the unasyncd build that carries the
# asyncio->threading Lock transform.
unasync:
	uv run unasyncd

# Fail if the committed sync mirror has drifted from the async source.
unasync-check:
	uv run unasyncd --check

# Regenerate all codegen artifacts and fail on drift (CI drift gate).
codegen:
	uv run python -m codegen.check

check: lint typecheck unasync-check test

build:
	uv build

clean:
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
