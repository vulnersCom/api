"""GENERATED — the `scanner` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class ScannerBulletin(Bulletin):
    """`bulletinFamily: scanner` — adds the fields shared across this family."""

    pass


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
    nessus_severity: Any = Field(default=None, alias="nessusSeverity")
    """Severity as rated by the Nessus scanner."""
    patch_publication_date: Any = Field(default=None, alias="patchPublicationDate")
    """Date the fixing patch was published."""
    plugin_i_d: str | None = Field(default=None, alias="pluginID")
    """Scanner plugin identifier (e.g. Nessus plugin id)."""
    solution: str | None = None
    """Recommended remediation/fix, as text."""
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
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
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""


class NucleiBulletin(ScannerBulletin):
    """`type: nuclei` — Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""


class OpenvasBulletin(ScannerBulletin):
    """`type: openvas` — OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    nasl_family: str | None = Field(default=None, alias="naslFamily")
    """Nessus NASL plugin family."""
    plugin_i_d: str | None = Field(default=None, alias="pluginID")
    """Scanner plugin identifier (e.g. Nessus plugin id)."""
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""


class Rapid7Bulletin(ScannerBulletin):
    """`type: rapid7` — Rapid7 provides vulnerability data focused on various vendors and products, including advisories, CVEs, and exploit information."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cisa_kev: bool | None = Field(default=None, alias="cisaKev")
    """Whether Rapid7 marks the CVE as listed in CISA's Known Exploited Vulnerabilities catalog."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cross_references: list[str] | None = Field(default=None, alias="crossReferences")
    """Rapid7 cross-references to other sources, each as 'SOURCE/ID' (e.g. 'NVD/NVD', 'CWE/CWE-122')."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    exploited_in_wild: bool | None = Field(default=None, alias="exploitedInWild")
    """Whether Rapid7 records in-the-wild exploitation (its key for wildExploited)."""
    has_metasploit_module: bool | None = Field(default=None, alias="hasMetasploitModule")
    """Whether a Metasploit module exists for the issue; msfModuleCount holds how many."""
    has_poc: bool | None = Field(default=None, alias="hasPoc")
    """Whether Rapid7 knows of a public proof-of-concept (camelCase key for has_poc)."""
    has_rapid7_vm_coverage: bool | None = Field(default=None, alias="hasRapid7VmCoverage")
    """Whether Rapid7's vulnerability-management products detect the issue."""
    is_rapid7_critical: bool | None = Field(default=None, alias="isRapid7Critical")
    """Whether Rapid7's own rating marks the issue critical."""
    is_zero_day: bool | None = Field(default=None, alias="isZeroDay")
    """Whether Rapid7 recorded the issue as a zero-day."""
    msf_module_count: int | None = Field(default=None, alias="msfModuleCount")
    """Number of Metasploit modules Rapid7 counts for the issue."""
    rapid7_epss: Any = Field(default=None, alias="rapid7Epss")
    """Rapid7's copy of the EPSS forecast ('score' and 'percentile', both strings); an empty object when Rapid7 holds no EPSS data for the CVE."""
    rapid7_severity: Any = Field(default=None, alias="rapid7Severity")
    """Rapid7's own severity label — served empty on every document as of the last sampling, so prefer cvss/severity."""
    rapid7_updated_at: str | None = Field(default=None, alias="rapid7UpdatedAt")
    """Date Rapid7 last updated its record, as 'YYYY-MM-DD'."""
    solution: Any = None
    """Recommended remediation/fix, as text."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


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
    source_data: str | None = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""
