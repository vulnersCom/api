"""Single source of truth for the package version.

Kept in sync with ``[project].version`` in ``pyproject.toml`` by a CI check
(the two must match). Prefer importing ``vulners.__version__``.
"""

from __future__ import annotations

__version__ = "4.1.0"
__title__ = "vulners"
