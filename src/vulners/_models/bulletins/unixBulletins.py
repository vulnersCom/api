"""GENERATED — the `unix` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class UnixBulletin(Bulletin):
    """`bulletinFamily: unix` — adds the fields shared across this family."""

    pass


class AixBulletin(UnixBulletin):
    """`type: aix` — AIX collection from IBM includes security advisories and CVEs specifically for the AIX operating system."""

    aix_fileset: list | None = Field(default=None, alias="aixFileset")
    """Affected AIX filesets (fileset, product, version)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AlmalinuxBulletin(UnixBulletin):
    """`type: almalinux` — AlmaLinux vulnerability collection includes advisories and CVEs specific to AlmaLinux OS, sourced from official security bulletins."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AlpinelinuxBulletin(UnixBulletin):
    """`type: alpinelinux` — Alpine Linux vulnerability collection includes advisories and CVEs specific to Alpine Linux OS and its packages."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AltlinuxBulletin(UnixBulletin):
    """`type: altlinux` — AltLinux collection provides security advisories and CVEs specifically for Alt Linux OS, detailing vulnerabilities and patches for its software packages."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""


class AmazonBulletin(UnixBulletin):
    """`type: amazon` — Amazon's vulnerability collection includes security advisories and CVEs related to AWS services and products, focusing on cloud security issues."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ArchlinuxBulletin(UnixBulletin):
    """`type: archlinux` — Arch Linux security advisories and CVEs related to Arch Linux packages and systems, sourced from the Arch Linux security team."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AstralinuxBulletin(UnixBulletin):
    """`type: astralinux` — Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CblMarinerBulletin(UnixBulletin):
    """`type: cbl_mariner` — The CBL Mariner collection includes security advisories and CVEs specific to Microsoft's CBL Mariner Linux distribution."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CentosBulletin(UnixBulletin):
    """`type: centos` — CentOS vulnerability collection includes advisories and CVEs specific to CentOS OS, sourced from official vendor bulletins."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CgrBulletin(UnixBulletin):
    """`type: cgr` — CGR (Common Vulnerability Reporting) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CloudlinuxBulletin(UnixBulletin):
    """`type: cloudlinux` — CloudLinux provides security advisories and CVEs specific to CloudLinux OS, focusing on vulnerabilities affecting Linux-based web hosting environments."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class DebianBulletin(UnixBulletin):
    """`type: debian` — Debian vulnerability collection includes security advisories and CVEs specific to Debian OS packages and software components."""

    affected_package: Any = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class DebiancveBulletin(UnixBulletin):
    """`type: debiancve` — Debian Vulnerability Database (Debian VDE) provides security advisories and CVEs for Debian OS packages and related software vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class FedoraBulletin(UnixBulletin):
    """`type: fedora` — Fedora collection includes security advisories, CVEs, and patches for vulnerabilities affecting Fedora OS and its packages."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class FreebsdBulletin(UnixBulletin):
    """`type: freebsd` — FreeBSD vulnerability collection includes advisories and CVEs specific to FreeBSD operating system vulnerabilities and security updates."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class FreebsdAdvisoryBulletin(UnixBulletin):
    """`type: freebsd_advisory` — FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories."""

    affected_versions: Any = Field(default=None, alias="affectedVersions")
    """Affected version ranges."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class GentooBulletin(UnixBulletin):
    """`type: gentoo` — Gentoo collection includes vulnerability advisories and CVEs specific to Gentoo Linux packages and systems."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class MageiaBulletin(UnixBulletin):
    """`type: mageia` — Mageia security advisories provide information on vulnerabilities affecting Mageia Linux, including CVEs and patches for various software packages."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class MariadbunixBulletin(UnixBulletin):
    """`type: mariadbunix` — MariaDB Unix collection includes advisories and CVEs specific to Unix-based systems for the MariaDB database server."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    unofficial_repo: bool | None = None
    """Whether the fix comes from an unofficial repository."""


class OpensuseBulletin(UnixBulletin):
    """`type: opensuse` — OpenSUSE vulnerability collection includes advisories and CVEs related to OpenSUSE OS and its packages, sourced from the OpenSUSE security team."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class OpenwrtBulletin(UnixBulletin):
    """`type: openwrt` — OpenWrt vulnerability collection includes advisories and CVEs related to OpenWrt firmware, focusing on security issues affecting routers and embedded devices."""

    pass


class OraclelinuxBulletin(UnixBulletin):
    """`type: oraclelinux` — Oracle Linux vulnerabilities collection includes advisories and CVEs specific to Oracle Linux OS, sourced from Oracle's security bulletins."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class PhotonBulletin(UnixBulletin):
    """`type: photon` — Photon is a vulnerability collection from the National Vulnerability Database (NVD) focusing on vendor-specific advisories and CVEs related to various software products."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class RedhatBulletin(UnixBulletin):
    """`type: redhat` — Red Hat's vulnerability database provides advisories and CVEs related to Red Hat products and Linux distributions, focusing on security updates and patches."""

    affected_libraries: list | None = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    relates_to: str | None = Field(default=None, alias="relatesTo")
    """Identifier this document relates to."""


class RedosBulletin(UnixBulletin):
    """`type: redos` — Redos collection from various security databases focuses on vulnerabilities related to Regular Expression Denial of Service (ReDoS) across multiple vendors and products, typically including advisories and CVEs."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class RockyBulletin(UnixBulletin):
    """`type: rocky` — Rocky Linux vulnerability collection from the Rocky Linux project includes advisories and CVEs related to Rocky Linux OS security."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    fixes: list[str] | None = None
    """Fix references (fixed versions / patches)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class RosalinuxBulletin(UnixBulletin):
    """`type: rosalinux` — Rosalinux collection includes security advisories and CVEs specific to the Rosalyn Linux OS, sourced from the official Rosalyn security team."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SlackwareBulletin(UnixBulletin):
    """`type: slackware` — Slackware vulnerability collection includes advisories and CVEs specific to the Slackware Linux distribution, focusing on security issues in its packages."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SuseBulletin(UnixBulletin):
    """`type: suse` — SUSE vulnerability collection includes advisories and CVEs specific to SUSE Linux products and services, detailing security issues and patches."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SusecveBulletin(UnixBulletin):
    """`type: susecve` — SUSE CVE Database: Contains advisories and CVEs related to vulnerabilities in SUSE Linux products and services."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: Any = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    threats: Any = None
    """Threat-intelligence entries."""


class UbuntuBulletin(UnixBulletin):
    """`type: ubuntu` — Ubuntu vulnerability collection from the Ubuntu Security Notices, covering advisories and CVEs related to Ubuntu OS and its packages."""

    affected_package: Any = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class UbuntucveBulletin(UnixBulletin):
    """`type: ubuntucve` — Ubuntu CVE database provides security advisories and CVEs specifically for Ubuntu OS vulnerabilities."""

    affected_libraries: Any = Field(default=None, alias="affectedLibraries")
    """Affected libraries/packages (name, purl, version range)."""
    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    bugs: Any = None
    """Linked bug-tracker entries."""


class VirtuozzoBulletin(UnixBulletin):
    """`type: virtuozzo` — Virtuozzo collection includes security advisories and CVEs related to Virtuozzo virtualization software and its components."""

    affected_package: Any = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class WolfiBulletin(UnixBulletin):
    """`type: wolfi` — Wolfi is a vulnerability collection from the Wolfi project, focusing on Linux OS packages, typically containing advisories and CVEs."""

    affected_package: list | None = Field(default=None, alias="affectedPackage")
    """Affected OS/distribution packages (name, version, OS, arch)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
