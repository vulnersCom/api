"""Bulletin response models: a ``bulletinFamily`` discriminated hierarchy.

Construction stays validation-free (see :func:`construct_type`); this module adds
the family/version *shape* on top. A payload's ``type`` selects the most specific
per-collection model (:mod:`.collections`, generated), falling back to its
``bulletinFamily`` model here, with :class:`GenericBulletin` as the
forward-compatible fallback; a payload's CVSS ``version`` selects the matching
:class:`Cvss` subclass via the discriminator registry.

The model hierarchy is three levels — **base → family → type**:

* :class:`Bulletin` — the fields common to every document.
* the family models (:class:`CveBulletin`, :class:`ExploitBulletin`, …) — one per
  ``bulletinFamily``, extending the base. Every family the API emits is mapped in
  :data:`_FAMILY_MODELS`.
* the per-collection models in :mod:`.collections` — one per ``type``, extending
  its family model with the fields that collection adds.

Field descriptions come from attribute docstrings (see
:class:`~vulners._models._base.VulnersModel`), authored in
:mod:`vulners._models._field_descriptions` and kept in sync with live data by the
``dev-tools/data-models`` toolset. Fields are all optional and every model keeps
``extra="allow"``, so a document that carries an as-yet-unmodelled field never
loses data — the field is still accessible, just untyped.

An opt-in *strict* path (:func:`construct_bulletin` with ``strict=True``) runs
full pydantic validation: it selects the family model from :data:`_FAMILY_MODELS`
and validates through :meth:`~pydantic.BaseModel.model_validate` instead of the
construct fast path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pydantic import Field

from ._base import VulnersModel, construct_type, register_discriminator

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


# ---------------------------------------------------------------------------
# Bulletin base — the fields common to every bulletinFamily
# ---------------------------------------------------------------------------


class Bulletin(VulnersModel):
    """A single Vulners document; base for every ``bulletinFamily``.

    Carries the fields present across all families. Family subclasses add their
    own; ``extra="allow"`` keeps any unmodelled field accessible.
    """

    # --- identity ---
    id: str | None = None
    """Unique document identifier (e.g. a CVE id, exploit id or advisory id)."""
    type: str | None = None
    """Source collection the document comes from (cve, exploitdb, ubuntu, …)."""
    bulletin_family: str | None = Field(default=None, alias="bulletinFamily")
    """Broad family the document belongs to (cve, exploit, software, …)."""
    title: str | None = None
    """Human-readable title of the document."""
    description: str | None = None
    """Full text or summary of the vulnerability/advisory."""
    # --- links ---
    href: str | None = None
    """Canonical URL of the document at its original source."""
    vhref: str | None = None
    """URL of the document on vulners.com."""
    source_href: str | None = Field(default=None, alias="sourceHref")
    """URL of the raw source object, when it differs from href."""
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    # --- dates ---
    published: str | None = None
    """Original publication timestamp (ISO-8601)."""
    modified: str | None = None
    """Last modification timestamp at the source (ISO-8601)."""
    last_seen: str | None = Field(default=None, alias="lastseen")
    """Last time Vulners observed/refreshed the document (ISO-8601)."""
    timestamps: Timestamps | None = None
    """Vulners lifecycle timestamps (created/updated/enriched/reviewed/…)."""
    # --- scoring ---
    cvss: Cvss | None = None
    """Primary CVSS score block (version, base score, vector, severity, source)."""
    cvss2: Cvss | None = None
    """CVSS v2 score block."""
    cvss3: Cvss | None = None
    """CVSS v3.x score block."""
    cvss4: Cvss | None = None
    """CVSS v4.0 score block."""
    epss: list[EpssScore] | None = None
    """EPSS exploitation-probability forecast datapoints (score + percentile)."""
    metrics: Any | None = None
    """Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects)."""
    # --- linkage ---
    cvelist: list[str] | None = None
    """Related CVE identifiers referenced by this document."""
    references: list[str] | None = None
    """External reference URLs."""
    reporter: str | None = None
    """Person or organization credited with reporting/authoring it."""
    # --- provenance / enrichment ---
    source_available: bool | None = Field(default=None, alias="sourceAvailable")
    """Whether the raw source data is available for this document."""
    vendor_id: str | None = Field(default=None, alias="vendorId")
    """Vendor's own identifier for the advisory, when provided."""
    view_count: int | None = Field(default=None, alias="viewCount")
    """How many times the document has been viewed on Vulners."""
    enchantments: Enchantments | None = None
    """Vulners-computed enrichment layer (AI score, tags, related docs)."""
    attachments: list[Any] | None = None
    """Binary/media attachments associated with the document."""
    immutable_fields: list[str] | None = Field(default=None, alias="immutableFields")
    """Fields the source marks as immutable."""


class GenericBulletin(Bulletin):
    """Fallback for any family without a dedicated model (forward-compat)."""


class AdvisoryBulletin(Bulletin):
    """Vendor/CERT advisory shape (blog, cnnvd, cnvd, crypto, euvd, jvn, ncsc,
    nozomi, tools) — the base plus the affected-software / CPE fields these
    advisory sources add."""

    affected_software: list[Any] | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any | None = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CveBulletin(Bulletin):
    """``bulletinFamily: cve`` (or ``NVD``) — a CVE record and its scoring/enrichment."""

    cpe: list[str] | None = None
    """Affected products as CPE 2.2 URIs."""
    cpe23: list[str] | None = None
    """Affected products as CPE 2.3 formatted strings."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    affected_software: list[Any] | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    affected_configuration: list[Any] | None = Field(default=None, alias="affectedConfiguration")
    """Affected configuration entries."""
    cna_affected: list[Any] | None = Field(default=None, alias="cnaAffected")
    """Affected products as reported by the CNA (CVE JSON 5.x)."""
    cpe_configurations: Any | None = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    problem_types: list[Any] | None = Field(default=None, alias="problemTypes")
    """Structured problem-type/weakness records (CVE JSON 5.x)."""
    solutions: list[Any] | None = None
    """Structured remediation entries (CVE JSON 5.x)."""
    workarounds: list[Any] | None = None
    """Structured workaround entries when no fix is available."""
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    """NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …)."""
    web_applicability: Any | None = Field(default=None, alias="webApplicability")
    """Web-application applicability assessment."""
    ai_description: str | None = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    exploits: list[Any] | None = None
    """Related exploit records."""


class ExploitBulletin(Bulletin):
    """``bulletinFamily: exploit`` — exploit code / PoC and its provenance."""

    exploit_type: str | None = Field(default=None, alias="exploitType")
    """Type of exploit (remote, local, webapps, …)."""
    verified: bool | None = None
    """Whether the exploit/finding was verified."""
    has_poc: bool | None = Field(default=None, alias="has_poc")
    """Whether a proof-of-concept is available."""
    osvdbidlist: list[Any] | None = None
    """Legacy OSVDB identifiers."""
    affected_software: list[Any] | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""


class ScannerBulletin(Bulletin):
    """``bulletinFamily: scanner`` — a vulnerability-scanner plugin (Nessus, OpenVAS, …)."""

    cpe: list[str] | None = None
    """Affected products as CPE 2.2 URIs."""
    plugin_id: str | None = Field(default=None, alias="pluginID")
    """Scanner plugin identifier (e.g. Nessus plugin id)."""
    nasl_family: str | None = Field(default=None, alias="naslFamily")
    """Nessus NASL plugin family."""
    nessus_severity: str | None = Field(default=None, alias="nessusSeverity")
    """Severity as rated by the Nessus scanner."""
    cvss_score_source: str | None = Field(default=None, alias="cvssScoreSource")
    """Which party/standard the CVSS score was taken from."""
    exploit_available: bool | None = Field(default=None, alias="exploitAvailable")
    """Whether a public exploit is available."""
    solution: str | None = None
    """Recommended remediation/fix, as text."""
    affected_software: list[Any] | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""


class SoftwareBulletin(AdvisoryBulletin):
    """``bulletinFamily: software`` — an OS/vendor package or product advisory."""

    affected_package: list[Any] | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    severity: str | None = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""
    solution: str | None = None
    """Recommended remediation/fix, as text."""


class UnixBulletin(Bulletin):
    """``bulletinFamily: unix`` — a Linux/Unix distribution package advisory."""

    affected_package: list[Any] | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    affected_libraries: list[Any] | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_versions: Any | None = Field(default=None, alias="affectedVersions")
    """Affected version ranges."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    fixes: list[Any] | None = None
    """Fix references (fixed versions / patches)."""
    bugs: list[Any] | None = None
    """Linked bug-tracker entries."""


class InfoBulletin(Bulletin):
    """``bulletinFamily: info`` — threat intel, advisories and news write-ups
    (CISA KEV, blogs, vendor bulletins, exploitation reports)."""

    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    severity: str | None = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""
    tags: list[str] | None = None
    """Classification tags applied to the document."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""
    known_ransomware_campaign_use: str | None = Field(
        default=None, alias="knownRansomwareCampaignUse"
    )
    """Ransomware-campaign-use marker, as a string ('Known'/'Unknown', per CISA
    KEV) — not a boolean."""
    affected_software: list[Any] | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""


class LibraryBulletin(Bulletin):
    """``bulletinFamily: library`` — a package-ecosystem advisory (OSV, Snyk)."""

    affected_libraries: list[Any] | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    osv_affected: list[Any] | None = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    withdrawn: str | None = None
    """Withdrawal date if the advisory was retracted."""


class MicrosoftBulletin(Bulletin):
    """``bulletinFamily: microsoft`` — an MSRC/KB/update advisory."""

    kb: str | None = None
    """Microsoft Knowledge Base article id."""
    kb_list: list[str] | None = Field(default=None, alias="kbList")
    """Microsoft KB article ids covered by the update."""
    ms_severity: str | None = Field(default=None, alias="msseverity")
    """Microsoft's severity rating for the advisory."""
    ms_platform: str | None = Field(default=None, alias="msplatform")
    """Affected Microsoft platform."""
    superseeds: list[Any] | None = None
    """Updates this update supersedes."""
    parentseeds: list[Any] | None = None
    """Updates that supersede this update."""


class BugBountyBulletin(Bulletin):
    """``bulletinFamily: bugbounty`` — a bug-bounty / disclosure report."""

    bounty: Any | None = None
    """Bounty amount/details paid for the report."""
    bounty_state: str | None = Field(default=None, alias="bountyState")
    """State of the bounty (awarded, pending, …)."""
    cwe_id: str | None = None
    """Single associated CWE identifier."""
    repository: str | None = None
    """Source code repository associated with the report."""


# ``bulletinFamily`` -> concrete model. Every family the API emits is mapped here
# (kept in sync by dev-tools/data-models/sample_collections.py and enforced by
# tests/core/test_collections.py). ``NVD`` is the legacy tag for a CVE;
# near-identical advisory families share AdvisoryBulletin. An unmapped (new)
# family falls back to GenericBulletin — never an error.
_FAMILY_MODELS: dict[Any, type[Bulletin]] = {
    "cve": CveBulletin,
    "NVD": CveBulletin,
    "exploit": ExploitBulletin,
    "scanner": ScannerBulletin,
    "software": SoftwareBulletin,
    "unix": UnixBulletin,
    "info": InfoBulletin,
    "library": LibraryBulletin,
    "microsoft": MicrosoftBulletin,
    "bugbounty": BugBountyBulletin,
    "blog": AdvisoryBulletin,
    "cnnvd": AdvisoryBulletin,
    "cnvd": AdvisoryBulletin,
    "crypto": AdvisoryBulletin,
    "euvd": AdvisoryBulletin,
    "jvn": AdvisoryBulletin,
    "ncsc": AdvisoryBulletin,
    "nozomi": AdvisoryBulletin,
    "tools": AdvisoryBulletin,
}


# Per-collection (``type``) models live in ``collections.py`` and are built lazily
# by ``collection_model`` (one per type, on demand, cached). Resolved through this
# holder so a bulletin construction stays cheap and there's no import cycle
# (``collections`` imports this module); an import failure propagates loudly
# rather than silently degrading to family models.
_COLLECTION_MODEL: Callable[[object], type[Bulletin] | None] | None = None


def _collection_model(ctype: object) -> type[Bulletin] | None:
    """Build/return the per-collection model for *ctype* (cached factory), or None."""
    global _COLLECTION_MODEL
    if _COLLECTION_MODEL is None:
        from .collections import collection_model

        _COLLECTION_MODEL = collection_model
    return _COLLECTION_MODEL(ctype)


def _family_model(data: Any) -> type[Bulletin]:
    """Family model for *data*, read from ``bulletinFamily``/``bulletin_family``
    (mapping key or attribute), falling back to :class:`GenericBulletin`.

    The single family-selection helper shared by the strict and non-strict paths,
    so a snake_case round-trip (``model_dump()`` output) resolves identically on
    both. Tolerant of arbitrary values: a non-str family is the fallback.
    """
    if isinstance(data, Mapping):
        family = data.get("bulletinFamily", data.get("bulletin_family"))
    else:
        family = getattr(data, "bulletin_family", None)
    if isinstance(family, str):
        return _FAMILY_MODELS.get(family, GenericBulletin)
    return GenericBulletin


def bulletin_class_for(data: Any) -> type[Bulletin]:
    """Return the most specific model to build for *data*.

    A known ``type`` selects the per-collection model; otherwise the family
    (via :func:`_family_model`) is selected, falling back to
    :class:`GenericBulletin`. Never raises on malformed server data — an
    unusable ``type``/``bulletinFamily`` value just degrades the fallback chain.
    """
    if isinstance(data, Mapping):
        model = _collection_model(data.get("type"))
        if model is not None:
            return model
        return _family_model(data)
    return GenericBulletin


# Register Bulletin in the generic discriminator registry so ANY field annotated
# ``Bulletin`` (or list[Bulletin], …) specializes through construct_type exactly
# like a direct construct_bulletin call — same mechanism the CVSS union uses.
register_discriminator(
    Bulletin, "bulletinFamily", {}, GenericBulletin, resolver=bulletin_class_for
)


# ---------------------------------------------------------------------------
# Opt-in strict validation path
# ---------------------------------------------------------------------------


def construct_bulletin(data: Any, *, strict: bool = False) -> Bulletin:
    """Build the most specific :class:`Bulletin` for *data*.

    ``strict=True`` runs full pydantic validation: it selects the family model
    via :func:`_family_model` (the same helper the non-strict path uses) and
    validates through ``model_validate``. The default construct path never
    validates and prefers the per-collection (``type``) model when one exists.
    """
    if strict:
        return _family_model(data).model_validate(data)
    return construct_type(data, Bulletin)


__all__ = [
    "AdvisoryBulletin",
    "BugBountyBulletin",
    "Bulletin",
    "CveBulletin",
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "Enchantments",
    "EpssScore",
    "ExploitBulletin",
    "GenericBulletin",
    "InfoBulletin",
    "LibraryBulletin",
    "MicrosoftBulletin",
    "ScannerBulletin",
    "SoftwareBulletin",
    "Timestamps",
    "UnixBulletin",
    "bulletin_class_for",
    "construct_bulletin",
]
