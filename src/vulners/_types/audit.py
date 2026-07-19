"""Input TypedDicts for the audit resource.

These describe the structured software entries the audit endpoints accept.
Every audit method also accepts a plain CPE-like string in place of a dict.
"""

from __future__ import annotations

from typing import Literal

from typing_extensions import Required, TypedDict


class AuditItem(TypedDict, total=False):
    """A single software entry for ``audit.software`` / ``audit.host``."""

    part: Literal["a", "o", "h"]
    vendor: str
    product: Required[str]
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


class WinAuditItem(TypedDict):
    """A single installed-software entry for ``audit.win_audit``."""

    software: str
    version: str


__all__ = ["AuditItem", "WinAuditItem"]
