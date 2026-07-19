"""Async resource implementations (source of truth for the sync mirror).

Import concrete resources from their modules (e.g. ``.search``); this package
init stays import-free so the generated sync mirror needs no name rewriting here.
"""

from __future__ import annotations
