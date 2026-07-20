---
name: vulners-api-python-sdk
description: Use when modifying, testing, documenting, or reviewing the Vulners Python SDK. Covers the v4 architecture (typed sync/async clients, resource namespaces, bulletin model hierarchy, unasync codegen), the preserved legacy v3 surface, uv-based tooling, the 100% branch-coverage gate, safe API-key handling, and defensive vulnerability-intelligence examples.
---

# Vulners API Python SDK skill

## Purpose

Maintain the Vulners Python API SDK safely and consistently.

Use this skill for:

- Editing the `src/vulners/` package (v4 core or the legacy v3 layer).
- Adding SDK methods for Vulners API endpoints.
- Writing or updating tests under `tests/`.
- Updating examples in `samples/` and documentation under `documentation/`.
- Reviewing README changes, release automation, and API-key handling.

Do not use this skill for:

- Storing or generating real Vulners API keys.
- Writing exploit weaponization/execution code or operational abuse workflows.
- Moving non-runtime agent instructions into the `src/vulners/` package.

## Repository context

This skill is consumed from `.agents/skills/vulners-api/SKILL.md` by Codex-compatible
agent harnesses. This repository is the source of truth for the skill.

Current repository layout (src layout, `uv_build` backend):

```text
api/
├── .agents/skills/vulners-api/   # this skill
├── dev-tools/                    # maintainer tooling (not shipped)
├── documentation/                # mkdocs site source (Material theme)
├── samples/                      # runnable examples: v4/ and legacy/
├── src/vulners/                  # the shipped package
├── tests/                        # pytest suite (core, bc, live, benchmarks)
├── Makefile
├── mkdocs.yml
└── pyproject.toml
```

## Architecture

The primary API is the pair of typed clients in `src/vulners/_client.py`:

- `Vulners` (sync) and `AsyncVulners` (async), re-exported from the package root.
- Resources hang off each client as `cached_property` namespaces: `search`,
  `audit`, `archive`, `misc`, `report`, `stix`, `subscriptions`,
  `subscriptions_v4`, `webhooks`, `vscanner` (which nests `licenses`,
  `projects`, `projects.tasks`, `projects.results`).
- Each resource method declares its endpoint as a module-level `RequestSpec`
  (method, path, body mode, unwrap keys, timeout profile, rate-limit group) and
  routes through one shared request pipeline: credential-safety transport,
  retries with `Retry-After` support, and token-bucket rate-limit pacing.
- `client.get/post/put/delete` are untyped escape hatches for any API path.

**Async is the source of truth.** The sync mirror is generated:

- Hand-write async code in `src/vulners/_resources/_async/` (and
  `_transport_client_async.py`, `_ratelimit_async.py`).
- `make unasync` regenerates `src/vulners/_resources/_sync/` and the sync
  transport/ratelimit modules via `unasyncd` (mapping table in
  `[tool.unasyncd]` in `pyproject.toml`). Both sides are committed;
  `make unasync-check` gates drift in CI.
- Never hand-edit generated sync files — edit the async source and regenerate.

**Bulletin models** (`src/vulners/_models/`) form a base → family → per-collection
hierarchy:

- `Bulletin` — fields common to every document (hand-written, `bulletin.py`).
- Family models (`CveBulletin`, `ExploitBulletin`, …) — one per
  `bulletinFamily`, hand-written; `construct_bulletin` picks the right class.
- Per-collection models — one per collection `type`, built lazily by the
  factory in `collections.py` from generated data in `_collections_data.py`.
- Field descriptions live once in `_field_descriptions.py` and flow to models
  and reference docs. Refresh everything against the live API with
  `python dev-tools/data-models/sample_collections.py` (needs an API key).

**Legacy v3 surface** is preserved for backward compatibility: `base.py`,
`vscanner.py`, and the `src/vulners/vulners/` subpackage keep the old
`VulnersApi` / `VScannerApi` working unchanged (deprecated — new code should use
`Vulners` / `AsyncVulners`). The v3 layer is frozen: excluded from strict
typing and the coverage gate, guarded by the compatibility oracle in
`tests/bc/`. Do not extend it with new features.

An MCP server (`vulners-mcp` / `python -m vulners.mcp`) lives in
`src/vulners/_mcp/`, behind the optional `mcp` extra (`fastmcp`).

## Adding or changing an endpoint (v4)

1. Pick the resource module in `src/vulners/_resources/_async/` by API domain
   (`search.py`, `audit.py`, `archive.py`, `misc.py`, `report.py`, `stix.py`,
   `subscriptions*.py`, `webhooks.py`, `vscanner.py`).
2. Declare a module-level `RequestSpec` for the endpoint and add a typed async
   method with a Google-style docstring (args, returns, raises).
3. Run `make unasync` to regenerate the sync mirror.
4. Add tests (mocked HTTP via `respx`; no live calls) asserting URL, method,
   body, response parsing, and error paths. The v4 core is held at **100%
   branch coverage** — `make cov` must stay green.
5. Document the method (the mkdocs reference picks up docstrings; add how-to
   material under `documentation/` if the method is a common task) and add a
   sample under `samples/v4/` if it is commonly used.
6. Regenerate `api.md` if the public surface changed:
   `python dev-tools/generate_api_md.py`.

Backward compatibility: breaking changes only deliberately, documented in
release notes / CHANGELOG with the intended versioning impact.

## Tooling and quality commands

The project uses [uv](https://docs.astral.sh/uv/) with PEP 735 dependency
groups (`uv sync` installs the dev toolchain). Python >=3.10; ruff targets
py310 — do not use syntax or stdlib APIs unavailable on 3.10. Line length 98.

```bash
uv sync                # install project + dev groups
make format            # ruff format + import sorting
make lint              # ruff check + format --check
make typecheck         # mypy + basedpyright
make test              # full pytest suite, parallel (xdist)
make cov               # coverage gate: v4 core at 100% branch coverage
make cov-mcp           # MCP server coverage (isolated env with the mcp extra)
make bc                # backward-compatibility oracle only
make unasync           # regenerate the sync mirror from async sources
make unasync-check     # fail if the committed mirror drifted
make docs              # mkdocs build --strict (any warning fails)
make check             # lint + typecheck + unasync-check + test
```

`uv run pytest tests/<file>` runs a single module; `make test-fast` runs
serially for easier debugging.

## Testing expectations

Tests live in `tests/`:

- `tests/core/` and top-level `tests/test_*.py` — the v4 suite: mocked HTTP
  (`respx`), request construction, parsing, retries, rate limiting, streaming,
  secret handling. Deterministic; never require `VULNERS_API_KEY`.
- `tests/bc/` — the backward-compatibility oracle pinning the v3 surface and
  wire behavior against `surface.json` / golden files.
- `tests/live/` — opt-in live-API tests (marker `live`); the key comes from the
  `VULNERS_API_KEY` env var or the untracked `tests/live.local.toml`. Skipped
  by default; keep them minimal and read-only.
- `tests/benchmarks/` — pytest-codspeed micro-benchmarks, excluded from the
  default run.
- `tests/test_mcp.py` — MCP server tests; run in an isolated env
  (`make cov-mcp`) because `fastmcp` cannot share the default env.

Warnings are errors (`filterwarnings = ["error"]`): tests that intentionally
exercise deprecated shims must opt in locally with `pytest.warns(...)`, never
by weakening the global gate.

## Security rules

1. Never hardcode API keys, tokens, cookies, or credentials.
2. Use `VULNERS_API_KEY` from the environment in examples; live tests read it
   from the environment or `tests/live.local.toml` (untracked).
3. Mock HTTP responses for unit tests; live tests are opt-in and skipped by default.
4. Do not log API keys or full request headers. The SDK redacts the key in
   logs, strips it on cross-origin redirects, and keeps it out of reprs —
   preserve those guarantees when touching transport code.
5. Do not add offensive exploitation workflows; keep examples focused on
   defensive vulnerability intelligence.
6. Avoid committing real customer data, scan output from private systems, or
   proprietary asset inventories.

## Defensive example categories

Good examples: CVE lookup, bulletin lookup, vulnerability search, software
audit, Linux/Windows host audit, SBOM audit, CPE lookup, archive streaming,
error handling, pagination and rate-limit handling.

Avoid: exploit weaponization or execution (exploit metadata search is fine),
credential harvesting, unapproved scanning of third-party targets, examples
that disclose real infrastructure details.

## Definition of done

A change is ready when:

- The package imports successfully and `make check` passes.
- `make cov` stays at 100% for the v4 core; `make unasync-check` is clean.
- `make docs` builds strictly with no warnings.
- No secrets are committed.
- Public SDK methods have docstrings, docs, and (when commonly used) samples.
- Live network tests are opt-in only.
- The v3 compatibility surface is unchanged unless the change is intentionally
  breaking and documented.
