# How to connect the MCP server

The SDK ships a [Model Context Protocol](https://modelcontextprotocol.io) server, `vulners-mcp`,
so an AI client (Claude Desktop, Cursor, VS Code, Codex, …) can call Vulners as tools over stdio.
It exposes a core set of tools — search bulletins/exploits, look up a bulletin, and audit
software/Linux/CVEs — each returning compact, trimmed JSON.

!!! note "Bundled (self-hosted) vs. hosted"
    `vulners-mcp` here is a **minimal, self-hosted** server you run yourself. For a fully managed,
    always-on endpoint, use the official hosted server at
    [mcp.vulners.com](https://mcp.vulners.com/) — no install required (see
    [Hosted server](#hosted-server) below).

## Install and smoke-test

```bash
pip install "vulners[mcp]"     # the mcp extra carries fastmcp
export VULNERS_API_KEY=...      # a free key from https://vulners.com
vulners-mcp                     # serves MCP over stdio (Ctrl-C to stop)
```

The process talks JSON-RPC over stdin/stdout, so it looks idle in a terminal — that is expected.
Verify it with the Inspector below rather than by eye.

## Connect a client (stdio)

MCP clients launch the server as a subprocess and speak to it over stdio. Add an entry to the
client's MCP config; the shape is the same everywhere (`command` + `args` + `env`), only the file
location differs.

=== "Installed script"

    The simplest form once `pip install "vulners[mcp]"` has put `vulners-mcp` on `PATH`:

    ```json
    {
      "mcpServers": {
        "vulners": {
          "command": "vulners-mcp",
          "env": { "VULNERS_API_KEY": "YOUR_API_KEY_HERE" }
        }
      }
    }
    ```

=== "uvx (no install)"

    [`uv`](https://docs.astral.sh/uv/) fetches the package into a throwaway environment on each
    run — nothing to install or keep updated:

    ```json
    {
      "mcpServers": {
        "vulners": {
          "command": "uvx",
          "args": ["--from", "vulners[mcp]", "vulners-mcp"],
          "env": { "VULNERS_API_KEY": "YOUR_API_KEY_HERE" }
        }
      }
    }
    ```

    `pipx` works the same way: `pipx install "vulners[mcp]"`, then use `"command": "vulners-mcp"`.

=== "Docker"

    Build a tiny image (no Dockerfile ships in the package):

    ```dockerfile
    FROM python:3.13-slim
    RUN pip install --no-cache-dir "vulners[mcp]"
    ENTRYPOINT ["vulners-mcp"]
    ```

    ```bash
    docker build -t vulners-mcp .
    ```

    Then point the client at it — `-i` keeps stdin open for stdio, and `-e VULNERS_API_KEY`
    forwards the key from the client's `env` into the container:

    ```json
    {
      "mcpServers": {
        "vulners": {
          "command": "docker",
          "args": ["run", "-i", "--rm", "-e", "VULNERS_API_KEY", "vulners-mcp"],
          "env": { "VULNERS_API_KEY": "YOUR_API_KEY_HERE" }
        }
      }
    }
    ```

Where the config file lives, per client:

| Client | Config location |
|---|---|
| Claude Desktop | `claude_desktop_config.json` (Settings → Developer → Edit Config) |
| Cursor | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) |
| VS Code | `.vscode/mcp.json` (uses a top-level `"servers"` key instead of `"mcpServers"`) |
| Codex / other | the client's MCP/`mcpServers` config file |

After editing, restart (or reload) the client so it picks up the new server.

## How the API key is passed

`vulners-mcp` reads **`VULNERS_API_KEY` from its environment** — it takes no key on the command
line, so the key never lands in `args` or process listings. In a client config, set it in the
server's `env` block (as above); for Docker, forward it with `-e VULNERS_API_KEY` so it is not
baked into the image.

!!! warning "Keep configs with keys out of shared repos"
    A committed `.cursor/mcp.json` or `.vscode/mcp.json` with a real key leaks it. Prefer a
    per-user/global config, or reference an environment variable your client expands.

## Verify with the MCP Inspector

The official [MCP Inspector](https://github.com/modelcontextprotocol/inspector) launches the
server and lets you list and call its tools interactively:

```bash
VULNERS_API_KEY=... npx @modelcontextprotocol/inspector vulners-mcp
```

It opens a local UI where you can confirm the seven tools register and try a call (e.g.
`get_bulletin` with `id=CVE-2021-44228`).

## Tools

| Tool | Signature |
|---|---|
| `search_bulletins` | `(query, limit=10, offset=0)` — Lucene search; paginated (`total`/`has_more`/`next_offset`) |
| `search_exploits` | `(query, limit=10, offset=0)` — exploits/PoCs for a CVE or product |
| `get_bulletin` | `(id, fields=None, full=False)` — summary by default; `fields=[...]` or `full=True` for detail |
| `cve_lookup` | `(cve)` — CVE risk attributes (CVSS/CWE/CPE/EPSS) |
| `audit_software` | `(software, match="partial")` — vulnerabilities for CPE/software strings |
| `audit_linux` | `(os_name, os_version, packages)` — vulnerabilities for a Linux package list |
| `smart_audit` | `(software)` — free-form names → CPE/PURL + vulnerabilities (**billed per string**) |

Responses are trimmed for agents: long strings are clipped, long lists become a
`{items, total, truncated}` envelope, and searches page within the
[10,000-document window](../explanation/search-window.md). See
[`AGENTS.md`](https://github.com/vulnersCom/api/blob/master/AGENTS.md) for the full agent-facing
guide.

## Hosted server

For a managed, always-on endpoint with nothing to install, use the official hosted server at
**[mcp.vulners.com](https://mcp.vulners.com/)**. It is a remote (HTTP) MCP endpoint rather than a
local stdio subprocess, so it is added as a URL in clients that support remote servers; follow the
connection and authentication steps at [docs.vulners.com](https://docs.vulners.com/). The bundled
`vulners-mcp` above is the self-hosted alternative when you want the server inside your own
environment.
