"""GENERATED — the `info` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class InfoBulletin(Bulletin):
    """`bulletinFamily: info` — adds the fields shared across this family."""

    pass


class AmdBulletin(InfoBulletin):
    """`type: amd` — AMD's vulnerability collection includes advisories and CVEs related to AMD hardware and software products, focusing on security issues affecting their technology."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AttackerkbBulletin(InfoBulletin):
    """`type: attackerkb` — AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    attackerkb: Any = None
    """AttackerKB assessment (attacker value, exploitability)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    last_activity: str | None = None
    """Timestamp of the most recent activity on the item."""
    mitre_vector: Any = None
    """MITRE ATT&CK vector mapping."""
    references_categories: Any = None
    """References grouped by category (canonical/misc)."""
    tags: Any = None
    """Classification tags applied to the document."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""
    wild_exploited_category: Any = Field(default=None, alias="wildExploitedCategory")
    """Category of in-the-wild exploitation."""
    wild_exploited_reports: Any = Field(default=None, alias="wildExploitedReports")
    """Reports evidencing in-the-wild exploitation."""


class BduFstecBulletin(InfoBulletin):
    """`type: bdu_fstec` — BDU FSTEC provides advisories from the Russian Federal Service for Technical and Export Control, focusing on vulnerabilities in software and hardware products."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class BinamuseBulletin(InfoBulletin):
    """`type: binamuse` — Binamuse is a vulnerability collection from the Binamuse database focusing on advisories and CVEs related to various software products and systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CertBulletin(InfoBulletin):
    """`type: cert` — A collection of advisories and alerts from the Computer Emergency Response Team (CERT) covering various vendors and products, including CVEs and security incidents."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CheckpointAdvisoriesBulletin(InfoBulletin):
    """`type: checkpoint_advisories` — Checkpoint Advisories provide security bulletins from Check Point Software Technologies, including advisories and CVEs for their products."""

    protected_by: list[str] | None = None
    """Products/controls that protect against the issue."""
    severity: str | None = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""
    vulnerable_products: list[str] | None = None
    """Product identifiers known to be vulnerable."""


class CirclBulletin(InfoBulletin):
    """`type: circl` — CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    items: list | None = None
    """Sub-items/entries contained in the document."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""


class CisaBulletin(InfoBulletin):
    """`type: cisa` — CISA collection includes advisories and alerts from the Cybersecurity and Infrastructure Security Agency, focusing on vulnerabilities across various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""


class CisaKevBulletin(InfoBulletin):
    """`type: cisa_kev` — CISA KEV collection includes advisories and CVEs related to known exploited vulnerabilities across various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    due_date: str | None = Field(default=None, alias="dueDate")
    """Remediation due date (e.g. CISA KEV required-action deadline)."""
    known_ransomware_campaign_use: str | None = Field(
        default=None, alias="knownRansomwareCampaignUse"
    )
    """Ransomware-campaign-use marker, as a string ('Known'/'Unknown', per CISA KEV) — not a boolean."""
    notes: str | None = None
    """Free-text notes."""
    product: str | None = None
    """Affected product name."""
    required_action: str | None = Field(default=None, alias="requiredAction")
    """Required remediation action (e.g. CISA KEV directive)."""
    vendor: str | None = None
    """Affected product's vendor."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""


class CiscothreatsBulletin(InfoBulletin):
    """`type: ciscothreats` — Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cisco_threat: Any = Field(default=None, alias="ciscoThreat")
    """Cisco Talos threat details (files, hashes, subject)."""


class CoresecurityBulletin(InfoBulletin):
    """`type: coresecurity` — Core Security provides vulnerability advisories and CVEs focused on various software products and operating systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class Cve0dayBulletin(InfoBulletin):
    """`type: cve0day` — CVE0day is a collection from various sources focusing on zero-day vulnerabilities, typically including advisories and CVEs for multiple vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class DuoBulletin(InfoBulletin):
    """`type: duo` — Duo Security's collection features advisories and CVEs related to its authentication products and services, focusing on security vulnerabilities and fixes."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ErpscanBulletin(InfoBulletin):
    """`type: erpscan` — ERPSCAN provides security advisories and CVEs specifically focused on vulnerabilities in ERP systems and related applications."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class FireeyeBulletin(InfoBulletin):
    """`type: fireeye` — FireEye collection includes vendor-specific advisories and CVEs related to cybersecurity threats and exploits for various products and services."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class GoogleprojectzeroBulletin(InfoBulletin):
    """`type: googleprojectzero` — Google Project Zero collection features advisories and CVEs focused on vulnerabilities in various software products and operating systems."""

    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class HiveproBulletin(InfoBulletin):
    """`type: hivepro` — HivePro provides a comprehensive database of vulnerability advisories, CVEs, and threat intelligence focused on various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class IcsBulletin(InfoBulletin):
    """`type: ics` — This collection from the ICS-CERT includes advisories and CVEs related to vulnerabilities in industrial control systems across various vendors."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class IntelBulletin(InfoBulletin):
    """`type: intel` — Intel's vulnerability collection includes advisories and CVEs related to Intel products and technologies, focusing on hardware and software security issues."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    severity: str | None = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""


class KasperskyBulletin(InfoBulletin):
    """`type: kaspersky` — Kaspersky's collection includes security advisories and CVEs related to their antivirus products and software vulnerabilities."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class LenovoBulletin(InfoBulletin):
    """`type: lenovo` — Lenovo's vulnerability collection includes advisories and CVEs related to Lenovo products and software, sourced from their security bulletins."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class Myhack58Bulletin(InfoBulletin):
    """`type: myhack58` — MyHack58 provides security advisories and CVEs focused on vulnerabilities related to various software products and operating systems."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class PacketstormnewsBulletin(InfoBulletin):
    """`type: packetstormnews` — Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    source_href: str | None = Field(default=None, alias="sourceHref")
    """URL of the raw source object, when it differs from href."""


class PtsecurityBulletin(InfoBulletin):
    """`type: ptsecurity` — PTSecurity provides security advisories and CVEs focused on vulnerabilities affecting various software products and systems."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class QtBulletin(InfoBulletin):
    """`type: qt` — Qt vulnerabilities from the Qt Company, covering advisories and CVEs related to the Qt framework across various platforms and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class Rapid7blogBulletin(InfoBulletin):
    """`type: rapid7blog` — Rapid7 Blog provides insights on security vulnerabilities, advisories, and exploit techniques relevant to various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class RdotBulletin(InfoBulletin):
    """`type: rdot` — Rdot is a vulnerability collection from the Rdot database, focusing on advisories and CVEs related to various software products and operating systems."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class RedhatcveBulletin(InfoBulletin):
    """`type: redhatcve` — Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    source_affected_data: Any = Field(default=None, alias="sourceAffectedData")
    """Affected-product data in the source's own shape."""
    upstream_fix: Any = Field(default=None, alias="upstreamFix")
    """Whether/where an upstream fix is available."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class SambaBulletin(InfoBulletin):
    """`type: samba` — Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SecurityVulnsBulletin(InfoBulletin):
    """`type: security_vulns` — A collection of security vulnerabilities from various vendors, including advisories, CVEs, and exploit information."""

    pass


class SpringBulletin(InfoBulletin):
    """`type: spring` — Spring collection includes vulnerability advisories and CVEs related to the Spring framework and its ecosystem, sourced from various security bulletins."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class TalosBulletin(InfoBulletin):
    """`type: talos` — Talos provides threat intelligence from Cisco, focusing on vulnerabilities across various software and hardware products, including advisories and CVEs."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class TenableBulletin(InfoBulletin):
    """`type: tenable` — Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ThnBulletin(InfoBulletin):
    """`type: thn` — The \"thn\" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ThreatpostBulletin(InfoBulletin):
    """`type: threatpost` — Threatpost provides security news and analysis, focusing on vulnerabilities, exploits, and advisories across various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class TrellixBulletin(InfoBulletin):
    """`type: trellix` — Trellix provides security advisories and CVEs related to its cybersecurity products and services, focusing on vendor-specific vulnerabilities."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class VulncheckKevBulletin(InfoBulletin):
    """`type: vulncheck_kev` — Vulncheck_kev aggregates security advisories and CVEs from various vendors, focusing on known exploited vulnerabilities across multiple products."""

    product: str | None = Field(default=None, alias="_product")
    """Affected product name (source-internal key)."""
    vendor: str | None = Field(default=None, alias="_vendor")
    """Affected product's vendor (source-internal key)."""
    vulncheck_reported_exploitation: list | None = Field(
        default=None, alias="_vulncheck_reported_exploitation"
    )
    """VulnCheck-reported exploitation evidence."""
    vulncheck_xdb: list | None = Field(default=None, alias="_vulncheck_xdb")
    """VulnCheck exploit/DB cross-references."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cvss_score: float | None = Field(default=None, alias="cvssScore")
    """Flat numeric CVSS base score, when only a scalar is provided."""
    source: str | None = None
    """Source name/identifier for the record."""
    wild_exploited: bool | None = Field(default=None, alias="wildExploited")
    """Whether the vulnerability is exploited in the wild."""


class WizblogBulletin(InfoBulletin):
    """`type: wizblog` — Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class WordfenceBulletin(InfoBulletin):
    """`type: wordfence` — Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ZdiBulletin(InfoBulletin):
    """`type: zdi` — The ZDI collection includes advisories and CVEs from the Zero Day Initiative, focusing on vulnerabilities in various software products and vendors."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
