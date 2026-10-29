"""GENERATED — the `cvd` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class CvdBulletin(Bulletin):
    """`bulletinFamily: cvd` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    harness: str | None = None
    """Tooling credited with finding the issue in a coordinated-disclosure record (e.g. 'Claude Code', 'VulnForge')."""
    introduced_year: Any = Field(default=None, alias="introducedYear")
    """Year the flaw was introduced into the affected code, when the disclosure pins it down."""
    researcher: str | None = None
    """Researcher or team credited with the disclosure."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    status: str | None = None
    """Workflow status of the record."""
    vendor_severity: str | None = None
    """Vendor's own qualitative severity rating."""


class CvdCollectionBulletin(CvdBulletin):
    """`type: cvd` — CVD (Common Vulnerability Disclosure) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems."""

    pass
