"""GENERATED — the `cnvd` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class CnvdBulletin(Bulletin):
    """`bulletinFamily: cnvd` — adds the fields shared across this family."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    vendor_c_v_s_s: Any = Field(default=None, alias="vendorCVSS")
    """Vendor-assigned CVSS, as a raw string."""


class CnvdCollectionBulletin(CnvdBulletin):
    """`type: cnvd` — CNVD is a Chinese vulnerability database that provides advisories and CVEs focused on various software products and systems."""

    pass
