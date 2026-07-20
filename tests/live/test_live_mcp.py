"""Live tests for the Vulners MCP server tools against the real API (opt-in).

Exercises every tool the FastMCP server (``vulners._mcp.server``) exposes to LLM
agents, end to end through the real async client and the real Vulners API. Runs
only when both (a) the ``mcp`` extra (``fastmcp``) is installed and (b) a live key
is configured (``VULNERS_API_KEY`` or ``tests/live.local.toml``); otherwise it is
skipped. The mcp extra cannot share the default test env (its ``rich`` pin
conflicts with the codegen group), so run this in an isolated env, e.g.::

    uv run --no-default-groups --extra mcp --with pytest --with pytest-asyncio \
        pytest tests/live/test_live_mcp.py

Structural only (the DB is dynamic); the key is never asserted or logged.
``smart_audit`` bills per submitted string, so it is called with a single input.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.live

pytest.importorskip("fastmcp")

from vulners import AsyncVulners  # noqa: E402
from vulners._mcp import server  # noqa: E402

_CVE = "CVE-2021-44228"

_EXPECTED_TOOLS = (
    "search_bulletins",
    "get_bulletin",
    "search_exploits",
    "cve_lookup",
    "audit_software",
    "audit_linux",
    "smart_audit",
)


@pytest.fixture
async def live_mcp(live_config, monkeypatch):
    """The server module with ``_get_client`` bound to a real async client.

    Patching ``_get_client`` (rather than the ``VULNERS_API_KEY`` env) lets the
    client honor the configured ``base_url`` and get closed deterministically.
    """
    key, base_url = live_config
    async with AsyncVulners(api_key=key, base_url=base_url) as client:
        monkeypatch.setattr(server, "_get_client", lambda: client)
        yield server


async def _call(srv, name: str, **kwargs):
    tool = await srv.mcp.get_tool(name)
    return await tool.fn(**kwargs)


class TestMcpServerMetadata:
    async def test_all_expected_tools_registered(self, live_mcp):
        for name in _EXPECTED_TOOLS:
            tool = await live_mcp.mcp.get_tool(name)
            assert tool.name == name
            assert tool.description and len(tool.description) > 20

    def test_server_identity(self):
        assert server.mcp.name == "vulners"
        assert server.mcp.instructions


class TestMcpToolsLive:
    async def test_search_bulletins(self, live_mcp):
        res = await _call(live_mcp, "search_bulletins", query="type:cve", limit=3)
        assert isinstance(res, dict)
        assert isinstance(res["total"], int) and res["total"] >= 0
        assert res["returned"] <= 3
        assert isinstance(res["bulletins"], list)
        assert len(res["bulletins"]) == res["returned"]

    async def test_get_bulletin(self, live_mcp):
        res = await _call(live_mcp, "get_bulletin", id=_CVE)
        assert res is None or (isinstance(res, dict) and res["id"] == _CVE)

    async def test_get_bulletin_unknown_is_none(self, live_mcp):
        res = await _call(live_mcp, "get_bulletin", id="CVE-0000-00000")
        assert res is None

    async def test_search_exploits(self, live_mcp):
        res = await _call(live_mcp, "search_exploits", query="apache", limit=3)
        assert isinstance(res, dict)
        assert isinstance(res["total"], int) and res["total"] >= 0
        assert isinstance(res["exploits"], list)

    async def test_cve_lookup(self, live_mcp):
        res = await _call(live_mcp, "cve_lookup", cve=_CVE)
        assert res is None or (isinstance(res, dict) and res["id"] == _CVE)

    async def test_audit_software(self, live_mcp):
        res = await _call(
            live_mcp, "audit_software", software=["cpe:2.3:a:apache:http_server:2.4.49"]
        )
        assert isinstance(res, dict)
        assert isinstance(res["count"], int)
        assert isinstance(res["results"], list)

    async def test_audit_software_empty_short_circuits(self, live_mcp):
        res = await _call(live_mcp, "audit_software", software=[])
        assert res == {"count": 0, "results": []}

    async def test_audit_linux(self, live_mcp):
        res = await _call(
            live_mcp,
            "audit_linux",
            os_name="ubuntu",
            os_version="22.04",
            packages=["bash 5.1-6ubuntu1 amd64"],
        )
        assert isinstance(res, dict) and "result" in res

    async def test_smart_audit(self, live_mcp):
        # Preview endpoint — billing is per submitted string, so pass just one.
        res = await _call(live_mcp, "smart_audit", software=["nginx 1.18.0"])
        assert isinstance(res, dict)
        assert isinstance(res["count"], int)
        assert isinstance(res["results"], list)
