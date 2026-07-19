"""Vulners Model Context Protocol (MCP) server — the SDK's agentic layer.

Ships a `FastMCP <https://gofastmcp.com>`_ server that exposes a curated set of
Vulners tools (search, bulletin lookup, exploit search, software/host audit, CVE
lookup, smart audit) over the v4 async client, so an LLM agent can ground its
answers on live vulnerability intelligence.

This subpackage is intentionally private (underscore) and never imported by a
bare ``import vulners``: it only loads when the ``vulners-mcp`` console script
runs (or when :mod:`vulners._mcp.server` is imported explicitly). ``fastmcp`` is
an optional dependency, installed via the ``mcp`` extra::

    pip install "vulners[mcp]"
    VULNERS_API_KEY=... vulners-mcp

Keeping ``fastmcp`` out of this package's import graph means the core SDK stays
importable without the extra, and the backward-compatibility surface oracle
(which walks the package tree) can import this package without needing it.
"""

from __future__ import annotations
