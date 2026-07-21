"""GENERATED — the `tools` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class ToolsBulletin(Bulletin):
    """`bulletinFamily: tools` — adds the fields shared across this family."""

    tool_href: str | None = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""


class KitploitBulletin(ToolsBulletin):
    """`type: kitploit` — Kitploit is a security database focused on exploits and tools, primarily for penetration testing and ethical hacking, sourced from various contributors."""

    pass


class N0whereBulletin(ToolsBulletin):
    """`type: n0where` — n0where is a vulnerability database focusing on advisories and CVEs related to various software products and operating systems."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""
