# Vulners Python SDK

The official Python client for [Vulners](https://vulners.com) — the vulnerability
intelligence graph. Query CVEs, exploits and advisories enriched with CVSS, EPSS and
exploitation status; assess your software, hosts and SBOMs; and stream the whole graph into
your own pipelines — from a few lines of typed Python.

The SDK ships **two clients**:

- **v4 (recommended)** — modern, fully typed `Vulners` (sync) and `AsyncVulners` (async)
  clients with resource namespaces, response models, pagination and streaming.
- **v3 (legacy)** — the original `VulnersApi` / `VScannerApi` classes, kept for 100%
  backward compatibility. Existing code keeps working unchanged.

This site documents the **v4** client. If you are upgrading, see
[Migrating v3 → v4](explanation/migration.md).

## Install

```bash
pip install vulners
```

Requires **Python 3.10+**. A plain `pip install vulners` ships everything needed for fast,
modern transport out of the box — [`httpx`](https://www.python-httpx.org/),
[`pydantic`](https://docs.pydantic.dev/), [`orjson`](https://github.com/ijl/orjson), HTTP/2
(`h2`, on by default), response compression (`brotli`/`zstandard`), ISA-L-accelerated gzip
(`isal`) and multi-member zip streaming (`stream-unzip`) — all with prebuilt wheels, so there
is no build step. Optional extras:

| Extra | Adds |
|---|---|
| `vulners[mcp]` | a minimal, self-hosted `vulners-mcp` Model Context Protocol server (the official managed one is at [mcp.vulners.com](https://mcp.vulners.com/)) |
| `vulners[otel]` | opt-in OpenTelemetry tracing |

## Quickstart

Get a free API key at [vulners.com](https://vulners.com), then:

```python
from vulners import Vulners

with Vulners(api_key="YOUR_API_KEY_HERE") as v:
    for bulletin in v.search.query("type:exploit AND log4j", limit=5):
        print(bulletin.id, "—", bulletin.title)
```

The client also reads the key from the `VULNERS_API_KEY` environment variable, so you can
just write `Vulners()`.

Prefer `async`? The API is mirrored one-to-one:

```python
import asyncio
from vulners import AsyncVulners

async def main() -> None:
    async with AsyncVulners() as v:                # reads VULNERS_API_KEY
        cve = await v.search.get_bulletin("CVE-2021-44228")
        if cve is not None:
            print(cve.id, cve.cvss and cve.cvss.score)

asyncio.run(main())
```

## Where to next

<div class="grid cards" markdown>

- **[Quickstart tutorial](tutorials/quickstart.md)** — your first search and first audit,
  sync and async.
- **[How-to guides](how-to/audit-a-host.md)** — task-focused recipes: audit a host, stream the
  archive, search exploits, configure a proxy/timeouts/retries.
- **[API reference](reference/clients.md)** — every client, resource, model and exception.
- **[Explanation](explanation/network-and-rate-limits.md)** — the network & rate-limit model,
  the 10,000-document search window, the error model, and the v3→v4 migration guide.

</div>

## License

Distributed under the **MIT License**.
