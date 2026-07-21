"""GENERATED — the `nozomi` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class NozomiBulletin(Bulletin):
    """`bulletinFamily: nozomi` — adds the fields shared across this family."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class NozomiCollectionBulletin(NozomiBulletin):
    """`type: nozomi` — Nozomi Networks provides advisories and CVEs related to cybersecurity vulnerabilities in industrial control systems and critical infrastructure."""

    pass
