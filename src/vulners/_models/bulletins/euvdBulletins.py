"""GENERATED — the `euvd` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class EuvdBulletin(Bulletin):
    """`bulletinFamily: euvd` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cna_affected: list | None = Field(default=None, alias="cnaAffected")
    """Affected products as reported by the CNA (CVE JSON 5.x)."""


class EuvdCollectionBulletin(EuvdBulletin):
    """`type: euvd` — The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU."""

    pass
