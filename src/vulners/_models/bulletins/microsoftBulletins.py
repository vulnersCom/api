"""GENERATED — the `microsoft` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class MicrosoftBulletin(Bulletin):
    """`bulletinFamily: microsoft` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
    msrc: Any = None
    """Microsoft Security Response Center identifier."""


class MscveBulletin(MicrosoftBulletin):
    """`type: mscve` — MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products."""

    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    customer_action_required: bool | None = Field(default=None, alias="customerActionRequired")
    """Whether customer action is required."""
    cwe_list: Any = Field(default=None, alias="cweList")
    """Associated CWE weakness identifiers (alternate key)."""
    denial_of_service: str | None = Field(default=None, alias="denialOfService")
    """Denial-of-service impact marker, as a string (e.g. 'N/A') — not a boolean."""
    exploitability: Any = None
    """Exploitability assessment block."""
    faq: list[str] | None = None
    """Advisory FAQ entries."""
    impact: Any = None
    """Impact description/classification."""
    issuing_cna: str | None = Field(default=None, alias="issuingCna")
    """The CNA that issued the advisory."""
    kb_list: Any = Field(default=None, alias="kbList")
    """Microsoft KB article ids covered by the update."""
    mitigations: Any = None
    """Mitigation measures for the issue."""
    ms_affected_software: Any = Field(default=None, alias="msAffectedSoftware")
    """Affected Microsoft software entries."""
    ms_detail_revision: str | None = Field(default=None, alias="msDetailRevision")
    """Microsoft advisory detail revision."""
    mscve: str | None = None
    """Microsoft's CVE identifier for the advisory."""
    severity: Any = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""
    tag: str | None = None
    """A single classification tag."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class MskbBulletin(MicrosoftBulletin):
    """`type: mskb` — The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches."""

    affected_products: list[str] | None = Field(default=None, alias="affectedProducts")
    """Affected product names."""
    kb: str | None = None
    """Microsoft Knowledge Base article id."""
    mscve: str | None = None
    """Microsoft's CVE identifier for the advisory."""
    msfamily: str | None = None
    """Microsoft product family."""
    msimpact: str | None = None
    """Microsoft's impact classification."""
    msplatform: str | None = None
    """Affected Microsoft platform."""
    msproducts: list[str] | None = None
    """Affected Microsoft products."""
    msseverity: str | None = None
    """Microsoft's severity rating for the advisory."""
    parentseeds: list[str] | None = None
    """Updates that supersede this update."""
    primary_support_area_path: Any = Field(default=None, alias="primarySupportAreaPath")
    """Primary Microsoft support taxonomy path."""
    superseeds: list[str] | None = None
    """Updates this update supersedes."""
    support_area_path_nodes: Any = Field(default=None, alias="supportAreaPathNodes")
    """Microsoft support taxonomy nodes."""
    support_area_paths: Any = Field(default=None, alias="supportAreaPaths")
    """Microsoft support taxonomy paths."""


class MsupdateBulletin(MicrosoftBulletin):
    """`type: msupdate` — Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems."""

    bundled_updates: list[str] | None = Field(default=None, alias="bundledUpdates")
    """Updates bundled into this one."""
    kb: str | None = None
    """Microsoft Knowledge Base article id."""
    prerequisites_updates: list[str] | None = Field(default=None, alias="prerequisitesUpdates")
    """Prerequisite updates required before this one."""
    revision: str | None = None
    """Revision number of the advisory."""
    superseded_updates: list[str] | None = Field(default=None, alias="supersededUpdates")
    """Updates superseded by this one."""
