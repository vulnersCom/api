"""GENERATED base bulletin model — do not edit (see dev-tools/data-models)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .._base import VulnersModel
from .._nested import Cvss, Enchantments, EpssScore, Timestamps


class Bulletin(VulnersModel):
    """A single Vulners document; base for every bulletinFamily. Carries the fields present in every document. Family/type subclasses add their own; extra="allow" keeps any unmodelled field accessible."""

    bulletin_family: str | None = Field(default=None, alias="bulletinFamily")
    """Broad family the document belongs to (cve, exploit, software, …)."""
    cvelist: list[str] | None = None
    """Related CVE identifiers referenced by this document."""
    cvss: Cvss | None = None
    """Primary CVSS score block (version, base score, vector, severity, source)."""
    cvss2: Cvss | None = None
    """CVSS v2 score block."""
    cvss3: Cvss | None = None
    """CVSS v3.x score block."""
    cvss4: Cvss | None = None
    """CVSS v4.0 score block."""
    description: str | None = None
    """Full text or summary of the vulnerability/advisory."""
    enchantments: Enchantments | None = None
    """Vulners-computed enrichment layer (AI score, tags, related docs)."""
    epss: list[EpssScore] | None = None
    """EPSS exploitation-probability forecast datapoints (score + percentile)."""
    href: str | None = None
    """Canonical URL of the document at its original source."""
    id: str | None = None
    """Unique document identifier (e.g. a CVE id, exploit id or advisory id)."""
    immutable_fields: Any = Field(default=None, alias="immutableFields")
    """Fields the source marks as immutable."""
    lastseen: str | None = None
    """Last time Vulners observed/refreshed the document (ISO-8601)."""
    metrics: Any = None
    """Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects)."""
    modified: str | None = None
    """Last modification timestamp at the source (ISO-8601)."""
    published: str | None = None
    """Original publication timestamp (ISO-8601)."""
    references: list[str] | None = None
    """External reference URLs."""
    reporter: str | None = None
    """Person or organization credited with reporting/authoring it."""
    source_available: bool | None = Field(default=None, alias="sourceAvailable")
    """Whether the raw source data is available for this document."""
    timestamps: Timestamps | None = None
    """Vulners lifecycle timestamps (created/updated/enriched/reviewed/…)."""
    title: str | None = None
    """Human-readable title of the document."""
    type: str | None = None
    """Source collection the document comes from (cve, exploitdb, ubuntu, …)."""
    vendor_id: str | None = Field(default=None, alias="vendorId")
    """Vendor's own identifier for the advisory, when provided."""
    vhref: str | None = None
    """URL of the document on vulners.com."""
    view_count: int | None = Field(default=None, alias="viewCount")
    """How many times the document has been viewed on Vulners."""


class GenericBulletin(Bulletin):
    """Fallback for any bulletinFamily without a dedicated model (forward-compat)."""

    pass
