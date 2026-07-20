"""FastMCP server exposing Vulners intelligence to LLM agents.

Run it with the ``vulners-mcp`` console script (installed with the ``mcp``
extra) or ``python -m vulners._mcp.server``. The API key is read from the
``VULNERS_API_KEY`` environment variable.

Each tool is a thin, well-described wrapper over the v4 async client
(:class:`vulners.AsyncVulners`). Responses are trimmed to compact, agent-
friendly JSON — search/lookup tools select a small field set, and audit tools
run a schema-agnostic :func:`_compact` pass that clips long strings and caps
long lists — so a tool call never floods the model's context with a multi-
megabyte payload. Result sets are paginated: search tools return ``total`` and
the ``returned`` count so an agent can decide whether to narrow its query.
"""

from __future__ import annotations

from typing import Any, Literal

try:
    from fastmcp import FastMCP  # pyright: ignore[reportMissingImports]
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the extra
    raise ModuleNotFoundError(
        "The Vulners MCP server requires the optional 'mcp' extra. Install it with:\n"
        "    pip install 'vulners[mcp]'"
    ) from exc

from pydantic import BaseModel

from .._client import AsyncVulners
from .._models.bulletin import Bulletin
from .._resources._async.search import exploit_search_query

mcp: FastMCP[Any] = FastMCP(
    name="vulners",
    instructions=(
        "Vulnerability intelligence from Vulners (https://vulners.com). Use these "
        "tools to search CVEs, exploits and advisories, look up a bulletin by id, "
        "and audit software / Linux hosts / CVEs for known vulnerabilities. Results "
        "are trimmed for brevity; ask for a specific id to get its full record."
    ),
)

# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

_client: AsyncVulners | None = None


def _get_client() -> AsyncVulners:
    """Return a process-wide async client, building it from the environment once.

    The key comes from ``VULNERS_API_KEY`` (resolved by :class:`AsyncVulners`);
    a missing key raises :class:`vulners.VulnersError` on first use. Tests patch
    this function to inject a fake client.
    """
    global _client
    if _client is None:
        _client = AsyncVulners()
    return _client


# --------------------------------------------------------------------------- #
# Response trimming
# --------------------------------------------------------------------------- #

_MAX_STR = 800
_MAX_ITEMS = 20
_MAX_DEPTH = 8


def _compact(value: Any, *, depth: int = 0) -> Any:
    """Schema-agnostic size guard: clip long strings, cap long lists, bound depth.

    Audit endpoints return provider-shaped dicts whose ``vulnerabilities`` lists
    can be huge; this keeps a response compact without assuming a fixed schema.
    """
    if depth >= _MAX_DEPTH:
        return "…"
    if isinstance(value, str):
        return value if len(value) <= _MAX_STR else value[:_MAX_STR] + "…"
    if isinstance(value, list):
        trimmed = [_compact(v, depth=depth + 1) for v in value[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            trimmed.append(f"…(+{len(value) - _MAX_ITEMS} more of {len(value)})")
        return trimmed
    if isinstance(value, dict):
        return {k: _compact(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, BaseModel):
        # Typed sub-models (e.g. EpssScore rows) get the same clipping as raw
        # dicts and serialize uniformly at the MCP boundary.
        return _compact(value.model_dump(exclude_none=True), depth=depth)
    return value


def _cvss(cvss: Any) -> dict[str, Any] | None:
    if cvss is None:
        return None
    out: dict[str, Any] = {"score": getattr(cvss, "score", None)}
    severity = getattr(cvss, "severity", None)
    if severity is not None:
        out["severity"] = severity
    vector = getattr(cvss, "vector", None)
    if vector is not None:
        out["vector"] = vector
    version = getattr(cvss, "version", None)
    if version is not None:
        out["version"] = version
    return out


def _bulletin_summary(b: Bulletin) -> dict[str, Any]:
    """A compact, agent-friendly view of a bulletin."""
    desc = b.description
    return {
        "id": b.id,
        "title": b.title,
        "type": b.type,
        "family": b.bulletin_family,
        "cvss": _cvss(b.cvss),
        "published": b.published,
        "modified": b.modified,
        "href": b.href,
        "description": desc if desc is None or len(desc) <= _MAX_STR else desc[:_MAX_STR] + "…",
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


@mcp.tool
async def search_bulletins(query: str, limit: int = 10) -> dict[str, Any]:
    """Search Vulners with Lucene query syntax and return matching bulletins.

    Covers CVEs, advisories, exploits, blog posts and more. Example queries:
    ``type:cve AND cvss.score:[9 TO 10]``, ``affectedSoftware.name:nginx``,
    ``CISA KEV``, ``order:published``. See https://vulners.com/help for syntax.

    Args:
        query: A Vulners Lucene query.
        limit: Maximum bulletins to return in this page (1-100).

    Returns:
        ``{total, returned, bulletins, note}`` — ``total`` is the full match
        count; only ``returned`` compact summaries are included. The result
        window is capped at 10000 documents; narrow the query for more.
    """
    limit = max(1, min(limit, 100))
    page = await _get_client().search.query(query, limit=limit)
    return {
        "total": page.total,
        "returned": len(page.data),
        "bulletins": [_bulletin_summary(b) for b in page.data],
        "note": "Result window capped at 10000 docs; refine the query to narrow results.",
    }


@mcp.tool
async def get_bulletin(id: str) -> dict[str, Any] | None:
    """Fetch a single Vulners bulletin (CVE, advisory, exploit, ...) by its id.

    Args:
        id: The bulletin id, e.g. ``CVE-2021-44228`` or ``EDB-ID:50592``.

    Returns:
        A compact summary of the bulletin, or ``null`` if no such id exists.
    """
    bulletin = await _get_client().search.get_bulletin(id)
    return None if bulletin is None else _bulletin_summary(bulletin)


@mcp.tool
async def search_exploits(query: str, limit: int = 10) -> dict[str, Any]:
    """Find public exploits and proof-of-concept code matching a query.

    A convenience wrapper that restricts a Lucene search to the ``exploit``
    bulletin family. Pass a CVE id (``CVE-2023-20198``), a product name
    (``wordpress``), or any Lucene fragment.

    Args:
        query: A CVE id, product name, or Lucene fragment.
        limit: Maximum exploits to return (1-100).

    Returns:
        ``{total, returned, exploits, note}`` — compact exploit summaries.
    """
    limit = max(1, min(limit, 100))
    # Shares the SDK's exploit-query builder, so a bare CVE id is phrase-quoted
    # instead of being tokenized by Lucene into far-too-broad terms.
    page = await _get_client().search.query(exploit_search_query(query), limit=limit)
    return {
        "total": page.total,
        "returned": len(page.data),
        "exploits": [_bulletin_summary(b) for b in page.data],
        "note": "Result window capped at 10000 docs; refine the query to narrow results.",
    }


@mcp.tool
async def cve_lookup(cve: str) -> dict[str, Any] | None:
    """Look up a CVE and return its key risk attributes (CVSS, CWE, CPE, EPSS).

    Args:
        cve: A CVE identifier, e.g. ``CVE-2021-44228``.

    Returns:
        A compact CVE summary, or ``null`` if the CVE is unknown to Vulners.
    """
    bulletin = await _get_client().search.get_bulletin(cve)
    if bulletin is None:
        return None
    summary = _bulletin_summary(bulletin)
    # Enrich with CVE-specific fields when the row is a CveBulletin.
    for extra in ("cvss2", "cvss3"):
        value = getattr(bulletin, extra, None)
        if value is not None:
            summary[extra] = _cvss(value)
    for extra in ("cwe", "cpe", "epss", "cvelist"):
        value = getattr(bulletin, extra, None)
        if value is not None:
            summary[extra] = _compact(value)
    return summary


@mcp.tool
async def audit_software(software: list[str], match: str = "partial") -> dict[str, Any]:
    """Audit a list of software for known vulnerabilities.

    Each entry is a CPE 2.3 string (``cpe:2.3:a:apache:log4j:2.14.1``) or a
    simple ``product version`` / ``product`` string; the server matches them to
    products and returns the affecting vulnerabilities.

    Args:
        software: Software entries as CPE-like strings (at least one).
        match: ``"partial"`` (default) or ``"full"`` CPE matching.

    Returns:
        ``{count, results}`` — one trimmed result per matched product, each with
        its matched criteria and a capped list of affecting vulnerabilities.
    """
    if not software:
        return {"count": 0, "results": []}
    matching: Literal["partial", "full"] = "full" if match == "full" else "partial"
    results = await _get_client().audit.software(software, match=matching)
    return {"count": len(results), "results": _compact(results)}


@mcp.tool
async def audit_linux(os_name: str, os_version: str, packages: list[str]) -> dict[str, Any]:
    """Audit a Linux host's installed packages for known vulnerabilities.

    Args:
        os_name: Distribution name or id, e.g. ``ubuntu``, ``debian``, ``rhel``,
            ``alpine``.
        os_version: Distribution version, e.g. ``22.04``, ``10``.
        packages: Installed packages, one per entry, in the distro's native
            format — e.g. ``"openssl 1.1.1d-0+deb10u3 amd64"`` (dpkg) or
            ``"openssl-1.0.2k-19.el7.x86_64"`` (rpm). 1-2500 entries.

    Returns:
        The trimmed audit result (vulnerable packages, CVEs and fixes).
    """
    result = await _get_client().audit.linux_audit(
        os_name=os_name, os_version=os_version, packages=packages
    )
    return {"result": _compact(result)}


@mcp.tool
async def smart_audit(software: list[str]) -> dict[str, Any]:
    """Resolve free-form software names to CPE/PURLs and their vulnerabilities.

    Each input string is matched heuristically (no strict CPE required), e.g.
    ``"Apache HTTP Server 2.4.49"`` or ``"nginx 1.18.0"``.

    Note:
        Preview endpoint — **billing is per submitted string**, so keep the
        batch to what you need (1-500 entries, each at most 512 characters).

    Args:
        software: Free-form software strings to resolve and audit.

    Returns:
        ``{count, results}`` — per input: resolved cpe/purls, a confidence
        score, and a capped list of vulnerabilities.
    """
    results = await _get_client().audit.smart(software)
    return {"count": len(results), "results": _compact(results)}


def main() -> None:
    """Run the server over stdio (the default MCP transport)."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
