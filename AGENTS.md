# AGENTS.md — using the Vulners Python SDK

Guidance for AI agents (and their humans) using this SDK to work with the
[Vulners](https://vulners.com) vulnerability intelligence API. For contributor/development
conventions, see `.agents/skills/vulners-api/SKILL.md` instead.

## Install & authenticate

```bash
pip install vulners            # core
pip install "vulners[mcp]"     # + the MCP server (see below)
```

The API key comes from the `VULNERS_API_KEY` environment variable, or is passed explicitly.
Get a free key at <https://vulners.com>. Never hard-code a key in committed code.

## Two ways to use it

### 1. As a library

Prefer the **v4** clients: `Vulners` (sync) and `AsyncVulners` (async). Both are context
managers and expose the same resource namespaces.

```python
from vulners import Vulners

with Vulners() as v:                      # reads VULNERS_API_KEY
    # Search (Lucene syntax → typed Bulletin models; access fields as attributes)
    for b in v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=10):
        print(b.id, b.title, b.cvss and b.cvss.score)

    # Single lookup (-> Bulletin | None)
    cve = v.search.get_bulletin("CVE-2021-44228")

    # Audit software / Linux host
    v.audit.software(["cpe:2.3:a:apache:log4j:2.14.1"])
    v.audit.linux_audit(os_name="debian", os_version="10",
                        packages=["openssl 1.1.1d-0+deb10u3 amd64"])
```

Key entry points:

| Namespace | What it does | Common methods |
|---|---|---|
| `v.search` | search & fetch documents | `query`, `iter_query`, `get_bulletin`, `get_multiple_bulletins` |
| `v.audit` | vulnerability assessment | `software`, `host`, `linux_audit`, `library_audit`, `sbom_audit`, `cve_audit`, `kb_audit`, `win_audit`, `smart` |
| `v.archive` | bulk dataset download | `fetch_collection`, `iter_collection` (stream), `fetch_collection_update` |
| `v.misc` | lookups | `search_cpe`, `query_autocomplete`, `get_suggestion` |
| `v.report`, `v.stix`, `v.subscriptions`, `v.webhooks`, `v.vscanner` | reporting, STIX bundles, alerts, VScanner | — |

Notes for agents:

- **Pagination:** `search.query` returns a `SearchPage`; iterating it auto-paginates up to a
  hard **10,000-document** window. `page.total` is the full match count. For more than 10k
  documents, use `v.archive.iter_collection(...)` (async: `aiter_collection`), not search.
- **Errors:** everything raises a subclass of `VulnersError` (`RateLimitError` carries
  `.retry_after`; `APIStatusError` carries `.status_code` / `.error_code` / `.message`). The
  API key is redacted from error payloads.
- **`audit.smart` is billed per submitted string** — keep batches small.
- The legacy **v3** API (`VulnersApi`) still works unchanged; new agent code should use v4.

Full docs: build the site with `mkdocs build` (source under `documentation/`), or read
`documentation/` directly. See `documentation/explanation/migration.md` for v3→v4.

### 2. As an MCP server

> The official, fully managed MCP endpoint is hosted at **https://mcp.vulners.com/** (no
> install, always on). The `vulners-mcp` server described below is a **minimal, self-hosted**
> build shipped with the SDK — it exposes the core set of tools listed here, for running in
> your own environment.

The SDK ships a [Model Context Protocol](https://modelcontextprotocol.io) server so an agent
can call Vulners as tools over stdio:

```bash
pip install "vulners[mcp]"
export VULNERS_API_KEY=...
vulners-mcp
```

Tools exposed (each returns compact, trimmed JSON):

| Tool | Purpose |
|---|---|
| `search_bulletins(query, limit=10)` | Lucene search across CVEs/advisories/etc. |
| `get_bulletin(id)` | fetch one bulletin by id |
| `search_exploits(query, limit=10)` | exploits/PoCs for a CVE or product |
| `cve_lookup(cve)` | CVE risk attributes (CVSS/CWE/CPE/EPSS) |
| `audit_software(software, match="partial")` | vulnerabilities for CPE/software strings |
| `audit_linux(os_name, os_version, packages)` | vulnerabilities for a Linux package list |
| `smart_audit(software)` | resolve free-form names → CPE/PURL + vulnerabilities (billed per string) |

The server module lives at `vulners._mcp.server` (private package; `fastmcp` is imported
lazily, so a bare `import vulners` never needs the `mcp` extra).
