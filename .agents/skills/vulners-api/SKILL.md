---
name: vulners-api-python-sdk
description: Use when modifying, testing, documenting, or reviewing the Vulners SDK / Vulners Python wrapper. Focus on API v3 wrapper behavior, safe API-key handling, typed Python, ruff/mypy, mocked HTTP tests, and defensive vulnerability-intelligence examples.
---

# Vulners API Python SDK skill

## Purpose

Maintain the Vulners Python API SDK safely and consistently.

Use this skill for:

- Editing the `vulners/` Python package.
- Adding SDK methods for Vulners API v3 endpoints.
- Updating examples in `samples/`.
- Writing tests for request construction, response handling, rate-limit handling, validation, and error handling.
- Reviewing documentation, README changes, and API-key handling.
- Creating CI, lint, type-check, and release automation.

Do not use this skill for:

- Storing or generating real Vulners API keys.
- Writing exploit weaponization/execution code or operational abuse workflows.
- Moving non-runtime agent instructions into the `vulners/` package directory.

## Repository context

This skill is consumed from `.agents/skills/vulners-api/SKILL.md` by Codex-compatible
agent harnesses. This repository is the source of truth for the skill.

Current repository layout:

```text
vulners-sdk/
├── .agents/skills/vulners-api/
├── samples/
├── scripts/
├── vulners/
├── README.md
├── AUTHORS
├── LICENSE
├── Makefile
└── pyproject.toml
```

Target create-if-needed locations:

- Human documentation: `docs/`
- Tests: `tests/`
- GitHub automation: `.github/`
- Contribution and security policies: `CONTRIBUTING.md`, `SECURITY.md`

Known project conventions:

- Runtime package: `vulners/`
- Primary Vulners API facade: `vulners/vulners/`
- VScanner API facade: `vulners/vscanner.py`
- Examples: `samples/`
- Project scripts: `scripts/`
- Skill-only helper scripts: `.agents/skills/vulners-api/scripts/`
- Package metadata: `pyproject.toml`
- Python compatibility: Python >=3.10
- Ruff target: `py313`; do not write syntax or stdlib usage incompatible with Python 3.10
- Runtime dependencies: `httpx`, `orjson`, `pydantic`
- Development tooling: `ruff`, `mypy`; add `pytest` before introducing pytest tests.

## Security rules

1. Never hardcode API keys, tokens, cookies, or credentials.
2. Use `VULNERS_API_KEY` from the environment in examples and optional integration tests.
3. Keep `.env.example` free of real secrets; never commit `.env`.
4. Mock HTTP responses for unit tests.
5. Live network/API-key tests must be marked separately and skipped by default.
6. Do not log API keys or full request headers.
7. Do not add offensive exploitation workflows; keep examples focused on defensive vulnerability intelligence.
8. Avoid committing real customer data, scan output from private systems, or proprietary asset inventories.

## Development rules

1. Keep SDK runtime code in `vulners/`.
2. Keep examples in `samples/`.
3. Keep reusable repository skills in `.agents/skills/`.
4. Keep tests in `tests/`.
5. Keep CI in `.github/workflows/`.
6. Use typed Python and explicit errors.
7. Preserve backward compatibility unless the change is intentionally breaking; document breaking changes in release notes, a changelog, or the PR description with the intended versioning impact.
8. Add or update documentation for every new public SDK method.
9. Prefer small, focused pull requests.
10. Prefer deterministic unit tests over live API calls.
11. Treat absent directories such as `docs/`, `tests/`, and `.github/` as create-if-needed, not guaranteed.

## SDK method checklist

When adding or changing a public method:

- Choose the module by API domain before editing:
  - `vulners/vulners/search.py`: bulletin lookup, vulnerability search, exploit metadata search, web vulnerability search.
  - `vulners/vulners/audit.py`: software, OS, KB, Windows, and host audit endpoints.
  - `vulners/vulners/misc.py`: autocomplete, suggestions, CPE search, and web application rules.
  - `vulners/vulners/archive.py`: archive, collection, distributive, and getsploit download helpers.
  - `vulners/vulners/subscription.py` and `subscription_v4.py`: subscription APIs.
  - `vulners/vulners/webhook.py`: webhook APIs.
  - `vulners/vulners/report.py`: report APIs.
  - `vulners/vulners/stix.py`: STIX APIs.
  - `vulners/vscanner.py`: VScanner projects, tasks, results, licenses, and scanner-specific helpers.
- Add a new sub-API to `vulners/vulners/__init__.py` only when there is no existing domain fit.
- Confirm the endpoint path, method, request body, query parameters, and response shape.
- Add parameter validation where it prevents invalid API requests.
- Add typed request/response structures where practical.
- Test request construction without making a live network call.
- Test success responses.
- Test API error responses.
- Test timeout/retry/rate-limit behavior when relevant.
- Document the method in README or docs.
- Add a short sample if the method is commonly used.

## Testing expectations

For unit tests:

- Mock the HTTP client or use a transport mock.
- Assert URL/path, HTTP method, headers, and JSON body.
- Assert parsing of successful responses.
- Assert useful error messages for failed API responses.
- Do not require `VULNERS_API_KEY`.

For optional integration tests:

- Require `VULNERS_API_KEY`.
- Skip automatically when the variable is missing.
- Keep requests minimal and read-only.
- Avoid tests that depend on volatile search result counts.

For examples:

- Keep examples short and defensive.
- Use `os.environ["VULNERS_API_KEY"]` or `os.getenv("VULNERS_API_KEY")`.
- Explain whether the example performs live network calls.
- Avoid printing secrets or sensitive request headers.

## Quality commands

Use the commands supported by the repository. Current preferred checks:

```bash
poetry run ruff check vulners samples
poetry run ruff format --check vulners samples
poetry run mypy vulners
```

The Makefile exposes useful shortcuts:

```bash
make format
make isort
make mypy
make cc
```

There is no `pytest` dependency or `tests/` directory in the current project. If introducing tests,
propose adding `pytest` to the dev dependencies and creating `tests/` first.

The root `scripts/format` helper uses the declared ruff tooling. Prefer the Makefile and
ruff-based scripts unless a task explicitly updates the development dependency set.

If Poetry is not available in the environment, use equivalent local tooling without changing project configuration unnecessarily.

## Defensive example categories

Good examples:

- CVE lookup.
- Bulletin lookup.
- Vulnerability search.
- Software audit.
- Linux package audit.
- CPE lookup.
- API error handling.
- Pagination and rate-limit handling.

Avoid:

- Exploit weaponization or execution. Exploit metadata search examples are allowed when defensive.
- Credential harvesting.
- Unapproved scanning against third-party targets.
- Examples that disclose real infrastructure details.

## Definition of done

A change is ready when:

- The package imports successfully.
- Unit tests pass.
- Ruff and mypy pass where configured.
- No secrets are committed.
- Public SDK methods have docs or examples.
- Live network tests are opt-in only.
- The change preserves the repository's package layout.
