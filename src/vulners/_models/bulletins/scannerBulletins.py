"""GENERATED — the `scanner` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class ScannerBulletin(Bulletin):
    """`bulletinFamily: scanner` — adds the fields shared across this family."""

    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""


class NessusBulletin(ScannerBulletin):
    """`type: nessus` — Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe: list[str] | None = None
    """Affected products as CPE 2.2 URIs."""
    cvss_score_source: str | None = Field(default=None, alias="cvssScoreSource")
    """Which party/standard the CVSS score was taken from."""
    exploit_available: bool | None = Field(default=None, alias="exploitAvailable")
    """Whether a public exploit is available."""
    exploit_ease: str | None = Field(default=None, alias="exploitEase")
    """How easy exploitation is (scanner assessment)."""
    exploitable_with: Any = Field(default=None, alias="exploitableWith")
    """Tools/frameworks the issue is exploitable with."""
    nasl_family: str | None = Field(default=None, alias="naslFamily")
    """Nessus NASL plugin family."""
    nessus_severity: str | None = Field(default=None, alias="nessusSeverity")
    """Severity as rated by the Nessus scanner."""
    patch_publication_date: str | None = Field(default=None, alias="patchPublicationDate")
    """Date the fixing patch was published."""
    plugin_i_d: str | None = Field(default=None, alias="pluginID")
    """Scanner plugin identifier (e.g. Nessus plugin id)."""
    solution: str | None = None
    """Recommended remediation/fix, as text."""
    vendor_cvss2: Any = None
    """Vendor-assigned CVSS v2 (score/vector)."""
    vendor_cvss3: Any = None
    """Vendor-assigned CVSS v3 (score/vector)."""
    vpr: Any = None
    """Tenable Vulnerability Priority Rating block."""
    vulnerability_publication_date: str | None = Field(
        default=None, alias="vulnerabilityPublicationDate"
    )
    """Date the vulnerability itself was first published."""


class NmapBulletin(ScannerBulletin):
    """`type: nmap` — Nmap collection includes vulnerability data sourced from Nmap scans, focusing on various OS and services, typically containing CVEs and security advisories."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    nmap: Any = None
    """Nmap script details (category, script type)."""


class NucleiBulletin(ScannerBulletin):
    """`type: nuclei` — Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class OpenvasBulletin(ScannerBulletin):
    """`type: openvas` — OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    nasl_family: str | None = Field(default=None, alias="naslFamily")
    """Nessus NASL plugin family."""
    plugin_i_d: str | None = Field(default=None, alias="pluginID")
    """Scanner plugin identifier (e.g. Nessus plugin id)."""


class W3afBulletin(ScannerBulletin):
    """`type: w3af` — w3af is a vulnerability database focused on web application security, providing advisories, CVEs, and exploit information for various web technologies."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""
