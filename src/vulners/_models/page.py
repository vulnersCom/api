"""Backward-compatible re-export of the search page containers.

The page types now live in :mod:`vulners._pagination` (they carry cursor state
and a fetch callback). This module keeps the original import path working.
"""

from __future__ import annotations

from .._pagination import AsyncSearchPage, SearchPage

__all__ = ["AsyncSearchPage", "SearchPage"]
