<div align="center">

# 🛡️ Vulners Python SDK

### The official Python client for [Vulners](https://vulners.com) — the vulnerability intelligence graph to build on

Query CVEs, exploits and advisories enriched with CVSS, EPSS and exploitation status; assess your
software, hosts and SBOMs for the vulnerabilities that affect them; and stream the whole graph for
your own pipelines — all from a few lines of typed, async-ready Python.

[![PyPI version](https://img.shields.io/pypi/v/vulners?color=blue&label=pypi)](https://pypi.org/project/vulners/)
[![Python versions](https://img.shields.io/pypi/pyversions/vulners)](https://pypi.org/project/vulners/)
[![Downloads](https://img.shields.io/pypi/dm/vulners?color=blue)](https://pypi.org/project/vulners/)
[![CI](https://github.com/vulnersCom/api/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnersCom/api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/vulnersCom/api/blob/master/LICENSE)
[![Typed](https://img.shields.io/badge/typing-PEP%20561-brightgreen)](https://peps.python.org/pep-0561/)

[**SDK documentation**](https://vulnersCom.github.io/api/) ·
[**Data models**](https://vulnersCom.github.io/api/reference/bulletins/) ·
[**Get an API key**](https://docs.vulners.com/docs/quickstart/authentication/) ·
[**Vulners.com**](https://vulners.com)

</div>

---

## Why Vulners?

[Vulners](https://vulners.com) aggregates **230+ sources** — CVEs, exploits, vendor advisories,
CISA KEV, EPSS and AI risk scores — into one queryable vulnerability-intelligence graph, so you can
prioritize what to fix **beyond raw CVSS**. It is API-first and needs no agents or network access:
send asset data in standard formats, get back risk-prioritized intelligence.

This SDK is the fastest way to build on that graph from Python:

- 🔎 **Intelligence** — search and enrich CVEs, bulletins and advisories with CVSS, EPSS, KEV and exploitation context
- 🧨 **Exploits** — track active exploitation and pull proof-of-concept code for a product or CVE
- 🖥️ **Assessment** — find the vulnerabilities affecting your software, Linux/Windows hosts, KBs, libraries and SBOMs
- 🗄️ **Datasets** — stream the full graph (and hourly updates) into your own pipelines and mirrors
- 🔔 **Alerts** — subscribe to new vulnerabilities matching a query and get notified via webhook
- 🤖 **AI-ready** — a built-in [MCP server](#ai-agents-mcp) and fully typed responses to ground AI agents on live vulnerability facts

---

## Installation

```bash
pip install -U vulners
```

Requires **Python 3.10+**. The only runtime dependencies are
[`httpx`](https://www.python-httpx.org/), [`pydantic`](https://docs.pydantic.dev/) and
[`orjson`](https://github.com/ijl/orjson).

---

## Quickstart

```python
from vulners import Vulners

# Get a free API key at https://vulners.com (or export VULNERS_API_KEY).
with Vulners(api_key="YOUR_API_KEY_HERE") as v:
    # Look up a CVE — you get back a typed model.
    log4shell = v.search.get_bulletin("CVE-2021-44228")
    print(log4shell.id, "—", log4shell.title)
    print(log4shell.cvss.score, log4shell.cvss.vector)

    # Search with Lucene syntax. `limit` is the page size; read the first page here
    # (iterating the page itself auto-paginates the whole result window).
    page = v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=10)
    for bulletin in page.data:
        print(bulletin.id, bulletin.title)
```

> **Tip:** keep your key out of source code — read it from the environment:
> ```python
> import os
> from vulners import Vulners
> v = Vulners(api_key=os.environ["VULNERS_API_KEY"])
> ```

### Async

The same API is available on `AsyncVulners`:

```python
import asyncio
from vulners import AsyncVulners

async def main():
    async with AsyncVulners(api_key="YOUR_API_KEY_HERE") as v:
        page = await v.search.query("Fortinet AND RCE", limit=20)
        for bulletin in page.data:
            print(bulletin.id, bulletin.title)

asyncio.run(main())
```

---

## Usage examples

Runnable scripts for every task live under
[`samples/`](https://github.com/vulnersCom/api/tree/master/samples) — a **v4** set and a matching
**v3 (legacy)** set, side by side.

### Find public exploits for a CVE

```python
for exploit in v.search.query("bulletinFamily:exploit AND CVE-2023-20198", limit=10).data:
    print(exploit.id, exploit.href)
```

### Audit installed software for known CVEs

```python
# Mix product/version dicts and raw CPE 2.3 strings.
for item in v.audit.software([{"product": "openssl", "version": "1.0.1"},
                              "cpe:2.3:a:apache:log4j:2.14.1"]):
    print(item["matched_criteria"], "->", len(item["vulnerabilities"]), "vulnerabilities")
```

### Audit a Linux host by installed packages

```python
report = v.audit.linux_audit(os_name="debian", os_version="10",
                             packages=["openssl 1.1.1d-0+deb10u3 amd64"])
for issue in report["issues"]:
    print(issue["package"])
```

### Stream the archive (lazily, without buffering gigabytes)

```python
for record in v.archive.iter_collection("cve"):
    ...  # each NDJSON record is yielded as it arrives
```

### Handle errors

```python
from vulners import Vulners, APIError, RateLimitError

try:
    with Vulners(api_key="YOUR_API_KEY_HERE") as v:
        cve = v.search.get_bulletin("CVE-2021-44228")
except RateLimitError as err:
    print("slow down; retry after", err.retry_after, "s")
except APIError as err:
    print(err.status_code, err.error_code, err.message)   # the server's problem description
```

---

## Data models

Every document the API returns is a **bulletin**, and the SDK models them in three typed layers,
so your editor and type checker know the exact shape at whatever level of detail you need:

- **`Bulletin`** — the base fields every document carries (`id`, `title`, `cvss`, `published`, …).
- **Family models** (`CveBulletin`, `ExploitBulletin`, `ScannerBulletin`, …) — one per
  `bulletinFamily`, adding that family's shared fields.
- **Collection models** — one per collection `type`, adding the fields specific to that source.

`search`/`archive`/`audit` return the most specific model that fits a document (`type` →
`bulletinFamily` → `Bulletin`). Every field is optional (a missing one is `None`) and every model
keeps `extra="allow"`, so a field the API adds before the SDK models it is still on the object —
nothing is ever dropped.

```python
from vulners import Vulners, CveBulletin

with Vulners() as v:                          # reads VULNERS_API_KEY
    cve = v.search.get_bulletin("CVE-2021-44228")
    if isinstance(cve, CveBulletin):
        print(cve.cwe)                        # typed, cve-specific field — IDE-completed
```

The full hierarchy — every family and collection with its fields, descriptions and examples,
generated from live data — is browsable in the
**[Data models reference](https://vulnersCom.github.io/api/reference/bulletins/)**.

---

## AI agents (MCP)

Ship live Vulners intelligence to AI agents and copilots via the built-in
[Model Context Protocol](https://modelcontextprotocol.io) server:

```bash
pip install "vulners[mcp]"
VULNERS_API_KEY=... vulners-mcp        # run the MCP server
```

It exposes concise, typed tools — search bulletins, look up a CVE, find exploits, and audit
software/Linux/hosts — that any MCP-compatible client (Claude, IDE agents, …) can call. See
[`AGENTS.md`](https://github.com/vulnersCom/api/blob/master/AGENTS.md).

> **Hosted vs. bundled.** For a fully managed, always-on endpoint, use the official hosted
> server at **<https://mcp.vulners.com/>** — no install required. The `vulners-mcp` shipped
> in this package is a **minimal, self-hosted** implementation (a core set of tools) for
> embedding in your own environment.

---

## Backward compatibility

**Upgrading from 3.x is a drop-in.** The entire v3 API — `VulnersApi`, `VScannerApi`, every method,
and all import paths — is preserved unchanged in 4.0:

```python
import vulners
api = vulners.VulnersApi(api_key="YOUR_API_KEY_HERE")   # still works exactly as before
cve = api.search.get_bulletin("CVE-2021-44228")         # returns a dict, as it always did
```

New code should prefer the `Vulners` / `AsyncVulners` clients above. Migrate at your own pace — see
the [migration guide](https://vulnersCom.github.io/api/explanation/migration/).

---

## Getting an API key

1. Create a free account at **[vulners.com](https://vulners.com)**.
2. Follow the [authentication guide](https://docs.vulners.com/docs/quickstart/authentication/#how-to-obtain-api-key)
   to generate a key.
3. Pass it to `Vulners(api_key=...)`, or export `VULNERS_API_KEY` and let the client read it.

Never commit your API key. The SDK sends it only in the `X-Api-Key` header, strips it on
cross-origin redirects, refuses redirects to internal addresses, and keeps it out of exception
messages and object reprs.

---

## Documentation

| Resource | Link |
|---|---|
| 📘 SDK documentation | https://vulnersCom.github.io/api/ |
| 🧬 Data models (bulletin hierarchy) | https://vulnersCom.github.io/api/reference/bulletins/ |
| 🔌 SDK API reference (clients, resources, exceptions) | https://vulnersCom.github.io/api/reference/clients/ |
| 🧭 Migration (v3 → v4) | https://vulnersCom.github.io/api/explanation/migration/ |
| 📖 Vulners platform docs | https://docs.vulners.com/docs/ |
| 🧪 Interactive API (Swagger) | https://docs.vulners.com/docs/api/swagger/ |
| 🔑 Authentication / API keys | https://docs.vulners.com/docs/quickstart/authentication/ |
| 💡 Examples | [`samples/`](https://github.com/vulnersCom/api/tree/master/samples) |
| 🤝 Contributing | [CONTRIBUTING.md](https://github.com/vulnersCom/api/blob/master/CONTRIBUTING.md) |
| 🔒 Security policy | [SECURITY.md](https://github.com/vulnersCom/api/blob/master/SECURITY.md) |

---

## Compatibility

- **Python:** 3.10, 3.11, 3.12, 3.13, 3.14
- **Platforms:** Linux, macOS, Windows
- **Vulners API:** v3 and v4 endpoints

---

## Contributing

Issues and pull requests are welcome! Please open an issue to discuss substantial changes first.
The project uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync
make check   # lint + typecheck + unasync-check + tests
```

See [CONTRIBUTING.md](https://github.com/vulnersCom/api/blob/master/CONTRIBUTING.md) for the
full workflow.

---

## Security

Found a security issue in the SDK? Please report it privately — see
[SECURITY.md](https://github.com/vulnersCom/api/blob/master/SECURITY.md). Do not open a public
issue for vulnerabilities.

---

## License

Distributed under the **MIT License**. See
[LICENSE](https://github.com/vulnersCom/api/blob/master/LICENSE).

---

<div align="center">

**Built by the [Vulners](https://vulners.com) team.**
If this SDK helps secure your stack, please ⭐ the repo — it helps others find it.

<sub>Keywords: vulnerability intelligence · CVE · exploit intelligence · CVSS · EPSS · CISA KEV ·
risk prioritization · security advisories · SBOM · vulnerability assessment · vulnerability scanner ·
threat intelligence · vulnerability database · AI security agents · MCP · MSSP · DevSecOps ·
Python security · infosec</sub>

</div>
