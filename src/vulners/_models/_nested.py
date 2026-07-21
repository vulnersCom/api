"""Nested value objects shared across bulletin families.

These are hand-written framework, not generated: they carry bespoke structure and
logic that cannot be derived from samples — notably the CVSS-by-``version``
discriminator that picks the concrete :class:`Cvss` subclass. The generated
bulletin models (:mod:`.bulletins`) reference them by annotation (e.g. a ``cvss``
field is typed :class:`Cvss`); the emitter's rich-type map keeps those types wired
up wherever the field appears.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ._base import VulnersModel, register_discriminator

# ---------------------------------------------------------------------------
# CVSS — a union by Literal version
# ---------------------------------------------------------------------------


class Cvss(VulnersModel):
    """CVSS score block; the base/fallback across scoring versions."""

    version: str | None = None
    """CVSS specification version, e.g. '3.1'."""
    score: float | None = None
    """Base score, 0.0-10.0."""
    vector: str | None = None
    """CVSS vector string."""
    severity: str | None = None
    """Qualitative band (LOW/MEDIUM/HIGH/CRITICAL)."""
    source: str | None = None
    """Who assigned the score (CNA, NVD, …)."""


class Cvss2(Cvss):
    """CVSS v2 metrics."""


class Cvss3(Cvss):
    """CVSS v3.x metrics."""


class Cvss4(Cvss):
    """CVSS v4.0 metrics."""


# ``version`` picks the concrete model; an absent/unknown version stays ``Cvss``.
_CVSS_VERSIONS: dict[Any, type[Cvss]] = {
    "2.0": Cvss2,
    "3.0": Cvss3,
    "3.1": Cvss3,
    "4.0": Cvss4,
}
register_discriminator(Cvss, "version", _CVSS_VERSIONS, Cvss)


# ---------------------------------------------------------------------------
# Nested value objects shared across families
# ---------------------------------------------------------------------------


class Timestamps(VulnersModel):
    """Lifecycle timestamps Vulners maintains for a document (ISO-8601 strings)."""

    created: str | None = None
    """When Vulners first ingested the document."""
    updated: str | None = None
    """Last update of any kind."""
    enriched: str | None = None
    """Last enrichment pass."""
    reviewed: str | None = None
    """Last human/automated review."""
    content_updated: str | None = Field(default=None, alias="contentUpdated")
    """Last change to the document's content."""
    metrics_updated: str | None = Field(default=None, alias="metricsUpdated")
    """Last change to the document's scoring metrics."""
    web_applicability_updated: str | None = Field(default=None, alias="webApplicabilityUpdated")
    """Last change to the web-applicability assessment."""


class Enchantments(VulnersModel):
    """Vulners-computed enrichment layer over the raw document."""

    score: Any | None = None
    """Vulners AI/aggregated score block."""
    short_description: str | None = None
    """One-line summary."""
    tags: list[str] | None = None
    """Classification tags."""
    dependencies: Any | None = None
    """Related-document graph."""


class EpssScore(VulnersModel):
    """One EPSS (Exploit Prediction Scoring System) datapoint."""

    cve: str | None = None
    """CVE the forecast is for."""
    date: str | None = None
    """Date the forecast was computed."""
    epss: float | None = None
    """Probability of exploitation in the next 30 days (0.0-1.0)."""
    percentile: float | None = None
    """Percentile of this score among all scored CVEs."""


__all__ = [
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "Enchantments",
    "EpssScore",
    "Timestamps",
]
