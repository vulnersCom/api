"""GENERATED — the `library` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class LibraryBulletin(Bulletin):
    """`bulletinFamily: library` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class OsvAlbaBulletin(LibraryBulletin):
    """`type: osv_alba` — OSV-ALBA is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source software with advisories and CVEs."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvAleaBulletin(LibraryBulletin):
    """`type: osv_alea` — OSV-Alea aggregates vulnerability data from various sources, focusing on open-source software projects and providing advisories, CVEs, and exploit information."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvAlpineBulletin(LibraryBulletin):
    """`type: osv_alpine` — OSV Alpine is a vulnerability database focused on Alpine Linux, providing advisories and CVEs related to security issues in Alpine packages."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvAlsaBulletin(LibraryBulletin):
    """`type: osv_alsa` — OSV-ALS is a vulnerability collection from the Open Source Vulnerability Database focusing on advisories and CVEs related to the ALSA sound system."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvAsbBulletin(LibraryBulletin):
    """`type: osv_asb` — OSV ASB provides advisories and CVEs from various vendors, focusing on open-source vulnerabilities across multiple products and operating systems."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvAzlBulletin(LibraryBulletin):
    """`type: osv_azl` — OSV-AZL provides vulnerability advisories and CVEs specifically for Azure services and products, sourced from the Open Source Vulnerability database."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvBellBulletin(LibraryBulletin):
    """`type: osv_bell` — OSV-Bell provides advisories and CVEs related to open-source vulnerabilities, focusing on various software projects and their dependencies."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: str | None = None
    """Withdrawal date if the advisory was retracted."""


class OsvBitBulletin(LibraryBulletin):
    """`type: osv_bit` — OSV Bit provides vulnerability data sourced from the Open Source Vulnerability database, focusing on open-source projects and typically includes advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvCanBulletin(LibraryBulletin):
    """`type: osv_can` — The osv_can collection from the Open Source Vulnerability Database includes advisories and CVEs related to open-source software vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: str | None = None
    """Withdrawal date if the advisory was retracted."""


class OsvCgaBulletin(LibraryBulletin):
    """`type: osv_cga` — OSV-CGA is a collection from the Open Source Vulnerability Database focusing on advisories and CVEs related to open-source software vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvCleanstartBulletin(LibraryBulletin):
    """`type: osv_cleanstart` — OSV Clean Start is a vulnerability database that aggregates CVEs and advisories focused on open-source projects and their dependencies."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvClsaBulletin(LibraryBulletin):
    """`type: osv_clsa` — OSV-CLSA provides vulnerability advisories and CVEs from various vendors and products, focusing on security issues across multiple software ecosystems."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvCurlBulletin(LibraryBulletin):
    """`type: osv_curl` — OSV database for cURL vulnerabilities, including advisories and CVEs related to the cURL software library."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: Any = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvCveBulletin(LibraryBulletin):
    """`type: osv_cve` — OSV-CVE is a vulnerability database that aggregates CVE advisories across various vendors and products, providing detailed vulnerability information."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: Any = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvDebianBulletin(LibraryBulletin):
    """`type: osv_debian` — OSV Debian provides security advisories and CVEs specifically for Debian OS vulnerabilities, sourced from the Debian security team."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvDlaBulletin(LibraryBulletin):
    """`type: osv_dla` — OSV DLA provides vulnerability advisories and CVEs for various open-source projects, sourced from the Open Source Vulnerability Database."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvDrupalBulletin(LibraryBulletin):
    """`type: osv_drupal` — OSV database for Drupal vulnerabilities, including advisories and CVEs related to Drupal core and contributed modules."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvDsaBulletin(LibraryBulletin):
    """`type: osv_dsa` — OSV-DSA provides security advisories and CVEs for various open-source projects, focusing on vulnerabilities affecting specific software packages."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvDtsaBulletin(LibraryBulletin):
    """`type: osv_dtsa` — OSV DTSA is a data source providing advisories and CVEs focused on vulnerabilities across various open-source software projects."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvEchoBulletin(LibraryBulletin):
    """`type: osv_echo` — OSV Echo is a vulnerability database that aggregates advisories and CVEs across various open-source projects and libraries."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvEefBulletin(LibraryBulletin):
    """`type: osv_eef` — The osv_eef collection from the Open Source Vulnerability Database includes advisories and CVEs related to open-source software vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvGhsaBulletin(LibraryBulletin):
    """`type: osv_ghsa` — OSV GHSA is a vulnerability collection from GitHub that includes advisories and CVEs related to security issues in open-source software projects."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvGoBulletin(LibraryBulletin):
    """`type: osv_go` — OSV Go is a vulnerability database sourced from the Open Source Vulnerability (OSV) database, focusing on Go language packages and typically includes CVEs and advisories."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvGsdBulletin(LibraryBulletin):
    """`type: osv_gsd` — OSV GSD provides vulnerability advisories and CVEs from various vendors, focusing on open-source software security issues."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvHsecBulletin(LibraryBulletin):
    """`type: osv_hsec` — OSV HSEC is a vulnerability database focusing on open-source software, providing advisories and CVEs related to security issues."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvJlsecBulletin(LibraryBulletin):
    """`type: osv_jlsec` — OSV.jlsec provides security advisories and CVEs specifically for Julia packages, focusing on vulnerabilities affecting the Julia programming environment."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvLsnBulletin(LibraryBulletin):
    """`type: osv_lsn` — OSV-LSN is a collection from the Open Source Vulnerability database focusing on vulnerabilities in open-source software, typically containing advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvMalBulletin(LibraryBulletin):
    """`type: osv_mal` — OSV-MAL is a vulnerability collection from the Open Source Vulnerability (OSV) database, focusing on malware-related advisories and CVEs across various software products."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvMgasaBulletin(LibraryBulletin):
    """`type: osv_mgasa` — OSV MGASA provides security advisories and CVEs for various software products and operating systems, sourced from the Mageia community."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvMiniBulletin(LibraryBulletin):
    """`type: osv_mini` — OSV Mini is a vulnerability data source providing concise advisories and CVEs focused on open-source projects and their dependencies."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvOesaBulletin(LibraryBulletin):
    """`type: osv_oesa` — OSV OESA provides advisories and CVEs related to open-source vulnerabilities, focusing on various open-source projects and their dependencies."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvOpensuseBulletin(LibraryBulletin):
    """`type: osv_opensuse` — OpenSUSE vulnerability data from OSV includes advisories and CVEs related to OpenSUSE products and their security issues."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvOsecBulletin(LibraryBulletin):
    """`type: osv_osec` — OSV OSEC provides security advisories and CVEs related to open-source software vulnerabilities across various projects and ecosystems."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvOsvBulletin(LibraryBulletin):
    """`type: osv_osv` — OSV (Open Source Vulnerability) database provides vendor-agnostic advisories and CVEs for open-source software vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvPsfBulletin(LibraryBulletin):
    """`type: osv_psf` — OSV-PSF is a vulnerability collection from the Open Source Vulnerability Database focusing on Python Software Foundation projects, including advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: Any = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvPubBulletin(LibraryBulletin):
    """`type: osv_pub` — OSV.Pub is a vulnerability database that aggregates advisories and CVEs across various open-source projects and ecosystems."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvPysecBulletin(LibraryBulletin):
    """`type: osv_pysec` — OSV Python Security (osv_pysec) provides advisories and CVEs related to vulnerabilities in Python packages, sourced from the Open Source Vulnerability (OSV) database."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvRhbaBulletin(LibraryBulletin):
    """`type: osv_rhba` — Red Hat Bugzilla advisories (RHBA) provide security updates and CVEs for Red Hat products, focusing on vulnerabilities and patches."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvRheaBulletin(LibraryBulletin):
    """`type: osv_rhea` — OSV Rhea aggregates vulnerability advisories and CVEs from various sources, focusing on open-source software projects and their dependencies."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvRhlwBulletin(LibraryBulletin):
    """`type: osv_rhlw` — OSV_RHLW is a collection from the Open Source Vulnerability database focusing on Red Hat Linux vulnerabilities, typically containing advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvRhsaBulletin(LibraryBulletin):
    """`type: osv_rhsa` — Red Hat Security Advisories (RHSA) provide security updates and advisories for Red Hat products, including CVEs and mitigation guidance."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvRlsaBulletin(LibraryBulletin):
    """`type: osv_rlsa` — OSV-RLSA is a vulnerability collection from the Open Source Vulnerability Database, focusing on advisories and CVEs related to open-source software."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvRootBulletin(LibraryBulletin):
    """`type: osv_root` — OSV Root is a vulnerability database that provides advisories and CVEs focused on open-source software projects and their dependencies."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: list | None = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvRsecBulletin(LibraryBulletin):
    """`type: osv_rsec` — OSV-RSEC is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source projects and containing advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvRustsecBulletin(LibraryBulletin):
    """`type: osv_rustsec` — The osv_rustsec collection from the RustSec database provides security advisories and CVEs specifically for Rust programming language packages."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvRxsaBulletin(LibraryBulletin):
    """`type: osv_rxsa` — OSV (Open Source Vulnerability) database collection focusing on open source software vulnerabilities, typically containing advisories and CVEs."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvSuseBulletin(LibraryBulletin):
    """`type: osv_suse` — OSV SUSE provides security advisories and CVEs specific to SUSE products, aiding in vulnerability assessment for SUSE operating systems."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvUbuntuBulletin(LibraryBulletin):
    """`type: osv_ubuntu` — OSV database for Ubuntu, covering security advisories and CVEs related to Ubuntu OS and its packages."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
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


class OsvUsnBulletin(LibraryBulletin):
    """`type: osv_usn` — OSV USN is a collection from the Open Source Vulnerability database focusing on advisories for Ubuntu OS vulnerabilities and associated CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: list | None = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: list[str] | None = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class OsvUviBulletin(LibraryBulletin):
    """`type: osv_uvi` — OSV UVI is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source projects and containing advisories and CVEs."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: list[str] | None = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: list | None = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: str | None = None
    """Withdrawal date if the advisory was retracted."""


class OsvV8Bulletin(LibraryBulletin):
    """`type: osv_v8` — OSV v8 is a vulnerability database from the Open Source Vulnerability (OSV) project, covering advisories and CVEs for open-source software projects."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    ecosystems: Any = None
    """Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …)."""
    osv_affected: Any = Field(default=None, alias="osvAffected")
    """OSV 'affected' ranges."""
    osv_cross_references: Any = Field(default=None, alias="osvCrossReferences")
    """OSV cross-references to other advisories."""
    osv_packages: Any = Field(default=None, alias="osvPackages")
    """OSV package records (ecosystem, name, purl)."""
    osv_severity: Any = Field(default=None, alias="osvSeverity")
    """OSV severity entries (score, type)."""
    purls: Any = None
    """Affected packages as Package-URL (purl) strings."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class SnykBulletin(LibraryBulletin):
    """`type: snyk` — Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
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
