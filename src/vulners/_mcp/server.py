"""Minimal FastMCP server exposing Vulners intelligence to LLM agents.

This is a small, self-hosted server bundled with the SDK, exposing a core set of
tools. The official, fully managed MCP endpoint is hosted at
https://mcp.vulners.com/ (no install required).

Run it with the ``vulners-mcp`` console script (installed with the ``mcp``
extra) or ``python -m vulners._mcp.server``. The API key is read from the
``VULNERS_API_KEY`` environment variable.

Each tool is a thin, well-described wrapper over the v4 async client
(:class:`vulners.AsyncVulners`). Responses are trimmed to compact, agent-
friendly JSON — search/lookup tools select a small field set, and audit tools
run a schema-agnostic :func:`_compact` pass that clips long strings and caps
long lists (a capped list becomes a ``{items, total, truncated}`` envelope) — so
a tool call never floods the model's context with a multi-megabyte payload.
Search tools are paginated: they take ``limit``/``offset`` and return
``total``/``has_more``/``next_offset`` so an agent can walk results or narrow
its query. ``get_bulletin`` returns a summary by default and accepts
``fields``/``full`` for more detail.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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


@asynccontextmanager
async def _lifespan(_server: Any) -> AsyncIterator[None]:
    """Close the shared async client (its connection pool) on server shutdown.

    In a plain stdio process the OS reclaims sockets on exit, but an embedded
    server, hot reload, or repeated init would otherwise leak pools and sockets.
    """
    try:
        yield
    finally:
        global _client
        if _client is not None:
            await _client.aclose()
            _client = None


mcp: FastMCP[Any] = FastMCP(
    name="vulners",
    lifespan=_lifespan,
    instructions=(
        "Vulnerability intelligence from Vulners (https://vulners.com). Use these "
        "tools to search CVEs, exploits and advisories, look up a bulletin by id, "
        "and audit software / Linux hosts / CVEs for known vulnerabilities. Results "
        "are trimmed for brevity; look up a specific id for a bulletin summary, and "
        "pass fields=[...] or full=true to get_bulletin for the fuller record."
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
# Dict cardinality cap. Generous enough for a whole bulletin document (full=True is
# ~45 keys) yet still bounds a pathological provider payload with thousands of keys.
_MAX_KEYS = 100
_MAX_DEPTH = 8

# Wire field names the compact summary is built from. Requested upstream when the
# caller asks get_bulletin for extra fields (or the full doc), so a field outside
# the server's default id-lookup projection is actually returned to enrich from.
_SUMMARY_FIELDS = (
    "id",
    "title",
    "type",
    "bulletinFamily",
    "cvss",
    "published",
    "modified",
    "href",
    "description",
)
# cve_lookup enriches the summary with these CVE-specific fields; request them so
# they are present regardless of the server's default projection.
_CVE_FIELDS = (*_SUMMARY_FIELDS, "cvss2", "cvss3", "cwe", "cpe", "epss", "cvelist")


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
            # Structured truncation: a self-describing envelope, never an ellipsis
            # string appended into an otherwise-homogeneous array (which would make
            # the array heterogeneous and awkward for a tool schema to consume).
            return {
                "items": trimmed,
                "returned": len(trimmed),
                "total": len(value),
                "truncated": True,
            }
        return trimmed
    if isinstance(value, dict):
        keys = list(value)
        items = {k: _compact(value[k], depth=depth + 1) for k in keys[:_MAX_KEYS]}
        if len(keys) > _MAX_KEYS:
            # Cap dict cardinality like lists, so a provider response with thousands
            # of keyed records cannot flood the context. Same self-describing shape.
            return {
                "items": items,
                "returned_keys": len(items),
                "total_keys": len(keys),
                "truncated": True,
            }
        return items
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
    clipped = False
    if desc is not None and len(desc) > _MAX_STR:
        clipped = True
        desc = desc[:_MAX_STR] + "…"
    summary: dict[str, Any] = {
        "id": b.id,
        "title": b.title,
        "type": b.type,
        "family": b.bulletin_family,
        "cvss": _cvss(b.cvss),
        "published": b.published,
        "modified": b.modified,
        "href": b.href,
        "description": desc,
    }
    if clipped:
        # Flag the clip so the agent knows to fetch the full field if it needs it.
        summary["description_truncated"] = True
    return summary


def _search_response(page: Any, key: str) -> dict[str, Any]:
    """Build the paginated envelope shared by the search tools.

    ``has_more``/``next_offset`` come from the page's window-aware
    :meth:`has_next_page`, so an agent can walk results with ``offset`` until the
    10000-document search window is exhausted.
    """
    has_more = page.has_next_page()
    out: dict[str, Any] = {
        "total": page.total,
        "offset": page.offset,
        "returned": len(page.data),
        "has_more": has_more,
        key: [_bulletin_summary(b) for b in page.data],
    }
    if has_more:
        out["next_offset"] = page.offset + page.limit
    return out


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


@mcp.tool
async def search_bulletins(query: str, limit: int = 10, offset: int = 0) -> dict[str, Any]:
    """Search Vulners with Lucene query syntax and return matching bulletins.

    Covers CVEs, advisories, exploits, blog posts and more. Example queries:
    ``type:cve AND cvss.score:[9 TO 10]``, ``affectedSoftware.name:nginx``,
    ``CISA KEV``, ``order:published``. See https://vulners.com/help for syntax.

    Args:
        query: A Vulners Lucene query.
        limit: Maximum bulletins to return in this page (1-100).
        offset: Number of matches to skip; pass the previous response's
            ``next_offset`` to page forward (the window is capped at 10000 docs).

    Returns:
        ``{total, offset, returned, has_more, next_offset, bulletins}`` —
        ``total`` is the full match count; only ``returned`` compact summaries are
        included. ``has_more`` is False once the 10000-document window is
        exhausted; narrow the query to reach matches beyond it.
    """
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    page = await _get_client().search.query(query, limit=limit, offset=offset)
    return _search_response(page, "bulletins")


@mcp.tool
async def get_bulletin(
    id: str, fields: list[str] | None = None, full: bool = False
) -> dict[str, Any] | None:
    """Fetch a single Vulners bulletin (CVE, advisory, exploit, ...) by its id.

    Returns a compact summary by default — id, title, type, family, cvss,
    timestamps, href and a clipped description. To pull more without flooding the
    context, name the fields you need in ``fields`` (wire names from the
    data-model reference, e.g. ``["cwe", "cpe", "epss", "cvelist",
    "affectedSoftware"]``), or pass ``full=True`` for the whole (size-guarded)
    document.

    Args:
        id: The bulletin id, e.g. ``CVE-2021-44228`` or ``EDB-ID:50592``.
        fields: Extra fields to add on top of the summary.
        full: Return the entire (size-guarded) document instead of a summary.

    Returns:
        The bulletin summary (optionally enriched via ``fields``), the full
        document when ``full`` is set, or ``null`` if no such id exists.
    """
    client = _get_client()
    if full:
        # Request the whole document (fields=["*"]) so `full` really means full —
        # not "whatever the server's default id-lookup projection happened to
        # include". The SDK's default get_bulletin omits heavy fields.
        bulletin = await client.search.get_bulletin(id, fields=["*"])
        if bulletin is None:
            return None
        return _compact(bulletin.model_dump(by_alias=True, exclude_none=True))
    if fields:
        # Ask the server for the summary fields plus the requested extras, so a
        # field outside the default projection is actually returned to enrich from
        # (not silently dropped because it was never fetched).
        requested = list(dict.fromkeys([*_SUMMARY_FIELDS, *fields]))
        bulletin = await client.search.get_bulletin(id, fields=requested)
    else:
        bulletin = await client.search.get_bulletin(id)
    if bulletin is None:
        return None
    summary = _bulletin_summary(bulletin)
    if fields:
        dumped = bulletin.model_dump(by_alias=True, exclude_none=True)
        for name in fields:
            if name in summary:
                continue
            value = dumped.get(name)
            if value is None:
                value = getattr(bulletin, name, None)
            if value is not None:
                summary[name] = _compact(value)
    return summary


@mcp.tool
async def search_exploits(query: str, limit: int = 10, offset: int = 0) -> dict[str, Any]:
    """Find public exploits and proof-of-concept code matching a query.

    A convenience wrapper that restricts a Lucene search to the ``exploit``
    bulletin family. Pass a CVE id (``CVE-2023-20198``), a product name
    (``wordpress``), or any Lucene fragment.

    Args:
        query: A CVE id, product name, or Lucene fragment.
        limit: Maximum exploits to return (1-100).
        offset: Number of matches to skip; pass the previous response's
            ``next_offset`` to page forward (the window is capped at 10000 docs).

    Returns:
        ``{total, offset, returned, has_more, next_offset, exploits}`` — compact
        exploit summaries with the same pagination fields as ``search_bulletins``.
    """
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    # Shares the SDK's exploit-query builder, so a bare CVE id is phrase-quoted
    # instead of being tokenized by Lucene into far-too-broad terms.
    page = await _get_client().search.query(
        exploit_search_query(query), limit=limit, offset=offset
    )
    return _search_response(page, "exploits")


@mcp.tool
async def cve_lookup(cve: str) -> dict[str, Any] | None:
    """Look up a CVE and return its key risk attributes (CVSS, CWE, CPE, EPSS).

    Args:
        cve: A CVE identifier, e.g. ``CVE-2021-44228``.

    Returns:
        A compact CVE summary, or ``null`` if the CVE is unknown to Vulners.
    """
    # Request the CVE-specific fields explicitly, so they are present regardless of
    # the server's default id-lookup projection (not just when it happens to include
    # them). Otherwise the enrichment below silently finds nothing.
    bulletin = await _get_client().search.get_bulletin(cve, fields=list(_CVE_FIELDS))
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
        # Do not report a false "0 vulnerabilities" success for an empty batch —
        # the SDK requires at least one item, and a silent no-op would let an agent
        # confidently conclude nothing is vulnerable when nothing was audited.
        raise ValueError("software must contain at least one entry")
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


@mcp.tool
async def audit_metadata(registry: str, name: str, version: str) -> dict[str, Any]:
    """Look up a single package's license and version-range metadata.

    Public on all plans. ``registry`` case is normalized; for Maven, ``name`` is the
    ``groupId:artifactId`` coordinate (a ``"/"`` is converted to ``":"``).

    Args:
        registry: Package registry, e.g. ``"pypi"``, ``"npm"``, ``"maven"``.
        name: Package name (for Maven, ``"groupId:artifactId"``).
        version: Package version, e.g. ``"2.28.0"``.

    Returns:
        ``{result, found}`` — ``result`` holds ``name``/``version``/``range``/``license``
        (a list); ``found`` is ``False`` when the registry does not know the package
        name (an empty license list with ``found`` true means "no recorded license").
    """
    result = await _get_client().audit.metadata(registry, name, version)
    return {"result": _compact(result), "found": result.found}


def main() -> None:
    """Run the server over stdio (the default MCP transport)."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
