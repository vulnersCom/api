"""Public entry point for the Vulners MCP server: ``python -m vulners.mcp``.

The server implementation lives in :mod:`vulners._mcp.server`; this module
re-exports it under a stable public name so it can be launched either way::

    vulners-mcp              # console script
    python -m vulners.mcp    # equivalent module form

Both require the ``mcp`` extra: ``pip install "vulners[mcp]"``. The API key is
read from the ``VULNERS_API_KEY`` environment variable.
"""

# The re-export needs the optional `mcp` extra (fastmcp), which cannot be
# installed in the default test environment, so this module is exercised by the
# isolated MCP test env (`make cov-mcp`) rather than the default coverage run.
from ._mcp.server import main, mcp  # pragma: no cover

__all__ = ["main", "mcp"]  # pragma: no cover

if __name__ == "__main__":  # pragma: no cover
    main()
