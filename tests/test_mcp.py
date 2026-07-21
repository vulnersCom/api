"""Tests for the Vulners MCP server (``vulners._mcp.server``).

The server lives behind the optional ``mcp`` extra, which carries ``fastmcp``.
``fastmcp`` cannot share an environment with the ``dev`` group's build-time
``unasyncd`` (conflicting ``rich`` pins), so it is *not* installed in the default
test environment and this module skips there. Run it in an isolated env::

    uv run --no-default-groups --extra mcp --with pytest --with pytest-asyncio \
        pytest tests/test_mcp.py

Kept deliberately out of the BC-oracle zone (``tests/bc``): it exercises the new
v4-only agentic layer, not the v3 compatibility surface.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("fastmcp")

from vulners._mcp import server
from vulners._models.bulletin import construct_bulletin

EXPECTED_TOOLS = {
    "search_bulletins",
    "get_bulletin",
    "search_exploits",
    "cve_lookup",
    "audit_software",
    "audit_linux",
    "smart_audit",
}


class _FakePage:
    """Minimal stand-in for the client's SearchPage."""

    def __init__(self, rows, total, offset=0, limit=10, has_more=False):
        self.data = rows
        self.total = total
        self.offset = offset
        self.limit = limit
        self._has_more = has_more

    def has_next_page(self):
        return self._has_more


@pytest.fixture
def fake_client(monkeypatch):
    """A MagicMock client with async resource methods, injected into the server."""
    client = MagicMock()
    monkeypatch.setattr(server, "_get_client", lambda: client)
    return client


async def test_expected_tools_registered():
    for name in EXPECTED_TOOLS:
        tool = await server.mcp.get_tool(name)
        assert tool.name == name
        # Each tool carries a real, non-trivial description (from its docstring).
        assert tool.description and len(tool.description) > 20


async def test_server_metadata():
    assert server.mcp.name == "vulners"
    assert server.mcp.instructions  # a non-empty agent-facing preamble


async def test_get_bulletin_calls_through(fake_client):
    row = construct_bulletin(
        {"id": "CVE-2021-44228", "title": "Log4Shell", "bulletinFamily": "NVD"}
    )
    fake_client.search.get_bulletin = AsyncMock(return_value=row)

    tool = await server.mcp.get_tool("get_bulletin")
    result = await tool.fn(id="CVE-2021-44228")

    fake_client.search.get_bulletin.assert_awaited_once_with("CVE-2021-44228")
    assert result["id"] == "CVE-2021-44228"
    assert result["title"] == "Log4Shell"
    assert result["family"] == "NVD"


async def test_get_bulletin_missing_returns_none(fake_client):
    fake_client.search.get_bulletin = AsyncMock(return_value=None)
    tool = await server.mcp.get_tool("get_bulletin")
    assert await tool.fn(id="CVE-0000-0000") is None


async def test_get_bulletin_fields_enriches_summary(fake_client):
    row = construct_bulletin(
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell",
            "bulletinFamily": "NVD",
            "cwe": ["CWE-502"],
            "cpe": ["cpe:2.3:a:apache:log4j:2.14.1"],
        }
    )
    fake_client.search.get_bulletin = AsyncMock(return_value=row)
    tool = await server.mcp.get_tool("get_bulletin")
    result = await tool.fn(
        id="CVE-2021-44228",
        fields=["cwe", "cpe", "id", "bulletin_family", "does_not_exist"],
    )

    # wire-name fields present in the by-alias dump are added on top of the summary
    assert result["cwe"] == ["CWE-502"]
    assert result["cpe"] == ["cpe:2.3:a:apache:log4j:2.14.1"]
    # a field already in the summary is left as-is (skipped, not duplicated)
    assert result["id"] == "CVE-2021-44228"
    # a snake_case attribute absent from the by-alias dump falls back to getattr
    assert result["bulletin_family"] == "NVD"
    # an unknown field is silently skipped
    assert "does_not_exist" not in result
    # the extras are actually requested upstream (not just filtered from whatever the
    # default projection happened to include) — the point of the fix
    forwarded = fake_client.search.get_bulletin.await_args.kwargs["fields"]
    assert {"cwe", "cpe", "bulletinFamily", "does_not_exist"} <= set(forwarded)


async def test_get_bulletin_full_returns_whole_document(fake_client):
    row = construct_bulletin(
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell",
            "bulletinFamily": "NVD",
            "cwe": ["CWE-502"],
        }
    )
    fake_client.search.get_bulletin = AsyncMock(return_value=row)
    tool = await server.mcp.get_tool("get_bulletin")
    result = await tool.fn(id="CVE-2021-44228", full=True)

    # the full dump uses wire (camelCase) names and includes non-summary fields
    assert result["id"] == "CVE-2021-44228"
    assert result["bulletinFamily"] == "NVD"
    assert result["cwe"] == ["CWE-502"]
    # full=True asks the server for the whole document, not the default projection
    assert fake_client.search.get_bulletin.await_args.kwargs["fields"] == ["*"]


async def test_get_bulletin_full_missing_returns_none(fake_client):
    fake_client.search.get_bulletin = AsyncMock(return_value=None)
    tool = await server.mcp.get_tool("get_bulletin")
    assert await tool.fn(id="CVE-0000-0000", full=True) is None


async def test_get_bulletin_flags_truncated_description(fake_client):
    long_desc = "x" * (server._MAX_STR + 100)
    row = construct_bulletin({"id": "CVE-2021-44228", "description": long_desc})
    fake_client.search.get_bulletin = AsyncMock(return_value=row)
    tool = await server.mcp.get_tool("get_bulletin")
    result = await tool.fn(id="CVE-2021-44228")

    assert result["description_truncated"] is True
    assert result["description"].endswith("…")
    assert len(result["description"]) == server._MAX_STR + 1  # clipped body + ellipsis


async def test_search_bulletins_shapes_and_clamps_limit(fake_client):
    rows = [construct_bulletin({"id": f"CVE-2099-{i:04d}", "title": f"t{i}"}) for i in range(3)]
    fake_client.search.query = AsyncMock(
        return_value=_FakePage(rows, total=1234, offset=0, limit=100, has_more=True)
    )

    tool = await server.mcp.get_tool("search_bulletins")
    result = await tool.fn(query="type:cve", limit=500)

    # limit is clamped into 1..100 before hitting the client
    _, kwargs = fake_client.search.query.call_args
    assert kwargs["limit"] == 100
    assert kwargs["offset"] == 0
    assert result["total"] == 1234
    assert result["offset"] == 0
    assert result["returned"] == 3
    assert result["has_more"] is True
    assert result["next_offset"] == 100  # offset + limit
    assert [b["id"] for b in result["bulletins"]] == [
        "CVE-2099-0000",
        "CVE-2099-0001",
        "CVE-2099-0002",
    ]


async def test_search_bulletins_paginates_with_offset(fake_client):
    rows = [construct_bulletin({"id": "CVE-2099-0100"})]
    fake_client.search.query = AsyncMock(
        return_value=_FakePage(rows, total=5, offset=90, limit=10, has_more=False)
    )
    tool = await server.mcp.get_tool("search_bulletins")
    result = await tool.fn(query="type:cve", limit=10, offset=90)

    # offset is forwarded to the client and echoed back
    _, kwargs = fake_client.search.query.call_args
    assert kwargs["offset"] == 90
    assert result["offset"] == 90
    assert result["has_more"] is False
    assert "next_offset" not in result  # omitted once the window is exhausted


async def test_search_exploits_restricts_to_exploit_family(fake_client):
    fake_client.search.query = AsyncMock(return_value=_FakePage([], total=0))
    tool = await server.mcp.get_tool("search_exploits")
    await tool.fn(query="CVE-2023-20198", limit=5)

    args, _ = fake_client.search.query.call_args
    # A bare CVE id is phrase-quoted (the SDK's shared exploit-query builder),
    # so Lucene matches it as one token instead of tokenizing it.
    assert args[0] == 'bulletinFamily:exploit AND ("CVE-2023-20198")'


async def test_search_exploits_leaves_plain_query_unquoted(fake_client):
    fake_client.search.query = AsyncMock(return_value=_FakePage([], total=0))
    tool = await server.mcp.get_tool("search_exploits")
    await tool.fn(query="wordpress")

    args, _ = fake_client.search.query.call_args
    assert args[0] == "bulletinFamily:exploit AND (wordpress)"


async def test_cve_lookup_enriches_cve_fields(fake_client):
    row = construct_bulletin(
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell",
            "bulletinFamily": "NVD",
            "cvss": {"score": 10.0, "severity": "CRITICAL", "version": "3.1"},
            "cvss3": {"score": 10.0},
            "cwe": ["CWE-502"],
            "cpe": ["cpe:2.3:a:apache:log4j:2.14.1"],
            "epss": [{"cve": "CVE-2021-44228", "epss": 0.97, "percentile": 0.999}],
        }
    )
    fake_client.search.get_bulletin = AsyncMock(return_value=row)
    tool = await server.mcp.get_tool("cve_lookup")
    result = await tool.fn(cve="CVE-2021-44228")

    assert result["cvss"] == {"score": 10.0, "severity": "CRITICAL", "version": "3.1"}
    assert result["cvss3"] == {"score": 10.0}
    assert result["cwe"] == ["CWE-502"]
    assert result["cpe"] == ["cpe:2.3:a:apache:log4j:2.14.1"]
    # epss rows are typed EpssScore models; _compact must dump them to plain
    # dicts so the tool result serializes uniformly at the MCP boundary.
    assert result["epss"] == [{"cve": "CVE-2021-44228", "epss": 0.97, "percentile": 0.999}]
    # the CVE-specific fields are requested upstream, so enrichment does not depend
    # on the server's default id-lookup projection
    forwarded = fake_client.search.get_bulletin.await_args.kwargs["fields"]
    assert {"cwe", "cpe", "epss", "cvss3"} <= set(forwarded)


async def test_audit_software_compacts_large_vuln_lists(fake_client):
    big = [{"id": f"CVE-2099-{i:04d}"} for i in range(50)]
    fake_client.audit.software = AsyncMock(
        return_value=[{"matched_criteria": "cpe:2.3:a:x", "vulnerabilities": big}]
    )
    tool = await server.mcp.get_tool("audit_software")
    result = await tool.fn(software=["cpe:2.3:a:x"], match="partial")

    fake_client.audit.software.assert_awaited_once()
    assert result["count"] == 1
    vulns = result["results"][0]["vulnerabilities"]
    # a capped list becomes a self-describing envelope, not a list ending in a string
    assert vulns["truncated"] is True
    assert vulns["total"] == 50
    assert vulns["returned"] == server._MAX_ITEMS
    assert len(vulns["items"]) == server._MAX_ITEMS


async def test_audit_software_empty_short_circuits(fake_client):
    fake_client.audit.software = AsyncMock()
    tool = await server.mcp.get_tool("audit_software")
    result = await tool.fn(software=[])
    assert result == {"count": 0, "results": []}
    fake_client.audit.software.assert_not_awaited()


async def test_smart_audit_passes_through(fake_client):
    fake_client.audit.smart = AsyncMock(return_value=[{"input": "nginx 1.18.0", "purls": []}])
    tool = await server.mcp.get_tool("smart_audit")
    result = await tool.fn(software=["nginx 1.18.0"])
    fake_client.audit.smart.assert_awaited_once_with(["nginx 1.18.0"])
    assert result["count"] == 1


def test_compact_depth_cap_and_scalar_passthrough():
    # A value nested beyond _MAX_DEPTH collapses to the ellipsis marker.
    nested: object = 1
    for _ in range(server._MAX_DEPTH + 2):
        nested = [nested]
    assert "…" in repr(server._compact(nested))
    # Scalars (non-str/list/dict) pass through unchanged.
    assert server._compact(42) == 42
    assert server._compact(None) is None


def test_compact_caps_dict_cardinality():
    # A dict with more than _MAX_KEYS keys is truncated to a self-describing envelope
    # so a provider payload with thousands of keys cannot flood the context.
    big = {f"k{i}": i for i in range(server._MAX_KEYS + 5)}
    out = server._compact(big)
    assert out["truncated"] is True
    assert out["total_keys"] == server._MAX_KEYS + 5
    assert out["returned_keys"] == server._MAX_KEYS
    assert len(out["items"]) == server._MAX_KEYS
    # a small dict is returned unchanged (no envelope)
    assert server._compact({"a": 1, "b": 2}) == {"a": 1, "b": 2}


async def test_lifespan_closes_client(monkeypatch):
    # The FastMCP lifespan closes and clears the shared async client on shutdown, so
    # embedded/hot-reload/repeated-init lifecycles do not leak the pool.
    closed = {}

    class _FakeClient:
        async def aclose(self):
            closed["aclosed"] = True

    monkeypatch.setattr(server, "_client", _FakeClient())
    async with server._lifespan(server.mcp):
        pass
    assert closed.get("aclosed") is True
    assert server._client is None


async def test_lifespan_without_client_is_noop(monkeypatch):
    # Shutdown when no client was ever built must not raise.
    monkeypatch.setattr(server, "_client", None)
    async with server._lifespan(server.mcp):
        pass
    assert server._client is None


def test_cvss_includes_vector_and_handles_none():
    class _C:
        score = 9.8
        severity = "CRITICAL"
        vector = "AV:N/AC:L"
        version = "3.1"

    assert server._cvss(_C()) == {
        "score": 9.8,
        "severity": "CRITICAL",
        "vector": "AV:N/AC:L",
        "version": "3.1",
    }
    assert server._cvss(None) is None


async def test_cve_lookup_missing_returns_none(fake_client):
    fake_client.search.get_bulletin = AsyncMock(return_value=None)
    tool = await server.mcp.get_tool("cve_lookup")
    assert await tool.fn(cve="CVE-0000-0000") is None


async def test_audit_linux_passes_through(fake_client):
    fake_client.audit.linux_audit = AsyncMock(
        return_value=[{"package": "openssl", "vulnerabilities": []}]
    )
    tool = await server.mcp.get_tool("audit_linux")
    result = await tool.fn(os_name="ubuntu", os_version="22.04", packages=["openssl 1.1.1"])
    fake_client.audit.linux_audit.assert_awaited_once_with(
        os_name="ubuntu", os_version="22.04", packages=["openssl 1.1.1"]
    )
    assert result["result"] == [{"package": "openssl", "vulnerabilities": []}]


def test_main_runs_server(monkeypatch):
    # main() must invoke the server's run() without blocking on stdio.
    ran = {}
    monkeypatch.setattr(server.mcp, "run", lambda: ran.setdefault("ran", True))
    server.main()
    assert ran["ran"]


def test_get_client_builds_async_client(monkeypatch):
    # _get_client constructs (and memoizes) an AsyncVulners from the env key.
    from vulners import AsyncVulners

    monkeypatch.setenv("VULNERS_API_KEY", "SYNTHETIC-MCP-KEY")
    monkeypatch.setattr(server, "_client", None)  # reset the process-wide cache
    client = server._get_client()
    assert isinstance(client, AsyncVulners)
    assert server._get_client() is client  # memoized on the second call
