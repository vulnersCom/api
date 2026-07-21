"""GENERATED — the `ncsc` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class NcscBulletin(Bulletin):
    """`bulletinFamily: ncsc` — adds the fields shared across this family."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class NcscCollectionBulletin(NcscBulletin):
    """`type: ncsc` — The NCSC collection includes UK government advisories and alerts on cybersecurity vulnerabilities across various vendors and products, featuring CVEs and mitigation guidance."""

    pass
