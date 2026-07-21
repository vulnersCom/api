"""GENERATED — the `library` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class LibraryBulletin(Bulletin):
    """`bulletinFamily: library` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class OsvBulletin(LibraryBulletin):
    """`type: osv` — OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class SnykBulletin(LibraryBulletin):
    """`type: snyk` — Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    snyk_data: Any = Field(default=None, alias="snykData")
    """Snyk-specific data (exploit maturity, malicious flag)."""


class VulnersosvBulletin(LibraryBulletin):
    """`type: vulnersosv` — Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them."""

    base_affected_library: Any = Field(default=None, alias="baseAffectedLibrary")
    """The primary affected library (name, purl, version range)."""
    snapshot_date: str | None = None
    """Date of the data snapshot this record was taken from."""
    transitive_affected_libraries: Any = Field(default=None, alias="transitiveAffectedLibraries")
    """Libraries affected transitively via dependencies."""
