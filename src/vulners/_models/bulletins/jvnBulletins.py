"""GENERATED — the `jvn` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class JvnBulletin(Bulletin):
    """`bulletinFamily: jvn` — adds the fields shared across this family."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class JvnCollectionBulletin(JvnBulletin):
    """`type: jvn` — The JVN collection provides advisories and CVEs related to vulnerabilities in various software products and operating systems sourced from Japan's security community."""

    pass
