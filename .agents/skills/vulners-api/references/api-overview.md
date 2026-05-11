# Vulners API SDK overview for maintainers

This repository is focused on the Vulners Python SDK. Agent skills should guide safe SDK
development; they should not replace the SDK, duplicate a separate MCP server, or contain secrets.

## Common SDK use cases

- Search vulnerability intelligence.
- Retrieve CVE or bulletin details.
- Audit software/package versions.
- Search CPEs.
- Query Linux package audit data.
- Handle pagination, rate limits, timeouts, and API errors.

## API key handling

Use the `VULNERS_API_KEY` environment variable in samples and optional integration tests. Older
examples used `KEY` or a hardcoded placeholder; treat `VULNERS_API_KEY` as the target convention.

Recommended local pattern:

```bash
export VULNERS_API_KEY="replace_with_real_key"
python samples/example.py
```

Recommended Python pattern:

```python
import os

api_key = os.getenv("VULNERS_API_KEY")
if not api_key:
    raise RuntimeError("Set VULNERS_API_KEY to run this example")
```

Do not:

- Commit real API keys.
- Put API keys in `SKILL.md`.
- Put API keys in README screenshots or test fixtures.
- Print full authorization headers.

## Public API layout

The top-level package exports `vulners.VulnersApi`, `vulners.VScannerApi`, and
`vulners.VulnersApiError`.

`VulnersApi` is composed from sub-APIs under `vulners/vulners/`:

- `search.py`: bulletin lookup, vulnerability search, exploit metadata search, web vulnerability search.
- `audit.py`: software, OS, KB, Windows, and host audit endpoints.
- `misc.py`: autocomplete, suggestions, CPE search, and web application rules.
- `archive.py`: archive, collection, distributive, and getsploit download helpers.
- `subscription.py` and `subscription_v4.py`: subscription APIs.
- `webhook.py`: webhook APIs.
- `report.py`: report APIs.
- `stix.py`: STIX APIs.

`vulners/vscanner.py` contains the separate `VScannerApi` facade for scanner projects, tasks,
results, licenses, and scanner-specific helpers.

## Unit test strategy

Prefer mocked HTTP tests. A unit test should verify that the SDK creates the expected request and handles the expected response, without relying on live Vulners API availability.

Live tests should be separate, opt-in, and read-only.
