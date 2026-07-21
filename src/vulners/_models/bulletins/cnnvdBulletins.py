"""GENERATED — the `cnnvd` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class CnnvdBulletin(Bulletin):
    """`bulletinFamily: cnnvd` — adds the fields shared across this family."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CnnvdCollectionBulletin(CnnvdBulletin):
    """`type: cnnvd` — CNNVD is a Chinese national vulnerability database that provides advisories and CVEs for various software products and systems."""

    pass
