"""GENERATED — the `crypto` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from .base import Bulletin


class CryptoBulletin(Bulletin):
    """`bulletinFamily: crypto` — adds the fields shared across this family."""

    vendor_severity: str | None = None
    """Vendor's own qualitative severity rating."""


class Code423n4Bulletin(CryptoBulletin):
    """`type: code423n4` — Code423n4 is a vulnerability database focused on security advisories and reports for smart contracts and blockchain projects."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
