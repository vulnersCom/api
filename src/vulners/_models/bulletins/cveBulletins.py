"""GENERATED — the `cve` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class CveBulletin(Bulletin):
    """`bulletinFamily: cve` — adds the fields shared across this family."""

    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""


class CveCollectionBulletin(CveBulletin):
    """`type: cve` — The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories."""

    affected_configuration: Any = Field(default=None, alias="affectedConfiguration")
    """Affected configuration entries."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: str | None = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    assigned: str | None = None
    """Assignment date/owner recorded by the source (e.g. CVE assignment)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cna_affected: Any = Field(default=None, alias="cnaAffected")
    """Affected products as reported by the CNA (CVE JSON 5.x)."""
    cna_cpe_applicability: Any = Field(default=None, alias="cnaCpeApplicability")
    """CPE applicability as supplied by the CNA."""
    cpe: Any = None
    """Affected products as CPE 2.2 URIs."""
    cpe23: Any = None
    """Affected products as CPE 2.3 formatted strings."""
    cpe_configuration: Any = Field(default=None, alias="cpeConfiguration")
    """Single CPE applicability configuration."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    exploits: Any = None
    """Related exploit records."""
    extra_references: list | None = Field(default=None, alias="extraReferences")
    """Additional reference URLs beyond the primary set."""
    impacts: list | None = None
    """Structured impact records (CVE JSON 5.x)."""
    origin: str | None = None
    """Ingestion origin/pipeline the record came through."""
    problem_types: Any = Field(default=None, alias="problemTypes")
    """Structured problem-type/weakness records (CVE JSON 5.x)."""
    solutions: Any = None
    """Structured remediation entries (CVE JSON 5.x)."""
    threat_data: Any = Field(default=None, alias="threatData")
    """Aggregated threat-intelligence signals."""
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    """NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …)."""
    web_applicability: Any = Field(default=None, alias="webApplicability")
    """Web-application applicability assessment."""
    workarounds: Any = None
    """Structured workaround entries when no fix is available."""


class CvelistBulletin(CveBulletin):
    """`type: cvelist` — CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata."""

    assigned: str | None = None
    """Assignment date/owner recorded by the source (e.g. CVE assignment)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cna_affected: Any = Field(default=None, alias="cnaAffected")
    """Affected products as reported by the CNA (CVE JSON 5.x)."""
    cna_cpe_applicability: Any = Field(default=None, alias="cnaCpeApplicability")
    """CPE applicability as supplied by the CNA."""
    date_updated: str | None = Field(default=None, alias="dateUpdated")
    """Source-reported last-update date."""
    exploits: Any = None
    """Related exploit records."""
    impacts: list | None = None
    """Structured impact records (CVE JSON 5.x)."""
    origin: str | None = None
    """Ingestion origin/pipeline the record came through."""
    provider: str | None = None
    """Organization that produced the record (e.g. the CNA)."""
    solutions: Any = None
    """Structured remediation entries (CVE JSON 5.x)."""
    workarounds: Any = None
    """Structured workaround entries when no fix is available."""


class NvdBulletin(CveBulletin):
    """`type: nvd` — The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    origin: str | None = None
    """Ingestion origin/pipeline the record came through."""
    source_references: list | None = None
    """References with their originating source."""
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    """NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …)."""


class PrionBulletin(CveBulletin):
    """`type: prion` — Prion collection includes advisories and CVEs related to vulnerabilities in software products from various vendors, focusing on security issues and exploits."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    sandbox_info: Any = Field(default=None, alias="sandboxInfo")
    """Sandbox detonation information."""


class VulnrichmentBulletin(CveBulletin):
    """`type: vulnrichment` — Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights."""

    adp_affected: Any = Field(default=None, alias="adpAffected")
    """Affected products as reported by an ADP (Authorized Data Publisher)."""
    assigned: str | None = None
    """Assignment date/owner recorded by the source (e.g. CVE assignment)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploits: Any = None
    """Related exploit records."""
    impacts: list | None = None
    """Structured impact records (CVE JSON 5.x)."""
    origin: str | None = None
    """Ingestion origin/pipeline the record came through."""
    provider: str | None = None
    """Organization that produced the record (e.g. the CNA)."""
    solutions: Any = None
    """Structured remediation entries (CVE JSON 5.x)."""
    workarounds: Any = None
    """Structured workaround entries when no fix is available."""
