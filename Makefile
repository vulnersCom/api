.PHONY: sync format lint typecheck test test-fast bc cov cov-mcp docs codegen unasync unasync-check check build clean

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
# fail_under=100 in [tool.coverage.report]). Scope is config-driven: bare --cov
# measures the whole package per [tool.coverage.run] (source + omit), so any new
# module is inside the gate by default; only the legacy v3 layer is omitted.
cov:
	uv run coverage erase
	uv run pytest -n auto --cov

# Branch-coverage gate for the MCP server, which lives behind the `mcp` extra
# (fastmcp) and cannot share the default env, so it is measured on its own.
cov-mcp:
	uv run --no-default-groups --extra mcp --with pytest --with pytest-asyncio --with pytest-cov \
		pytest tests/test_mcp.py --cov=vulners._mcp --cov-branch \
		--cov-report=term-missing --cov-fail-under=100

# Same scope as `cov` ([tool.coverage.run] omits the legacy v3 layer), but
# informational only — not gated. Kept as the no-fail variant of the report.
cov-all:
	uv run coverage erase
	uv run pytest -n auto --cov --cov-fail-under=0

# Regenerate the sync mirror (_ratelimit.py + resources/_sync + transport client)
# from the async source. unasyncd lives in the isolated `codegen` group (it pulls
# msgspec, kept out of the default dev sync), so run it with just that group.
unasync:
	uv run --no-default-groups --group codegen unasyncd

# Fail if the committed sync mirror has drifted from the async source.
unasync-check:
	uv run --no-default-groups --group codegen unasyncd --check

# Strict docs build (fails on any warning, incl. unresolved mkdocstrings refs).
docs:
	uv run --group docs mkdocs build --strict

# Regenerate all codegen artifacts and fail on drift (CI drift gate).
codegen:
	uv run python -m codegen.check

check: lint typecheck unasync-check test

build:
	uv build

clean:
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
