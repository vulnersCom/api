# `unix` family

**Model:** `UnixBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: unix`.

## Family fields

Present in every `unix` document, beyond the [common base](base.md).

_No fields beyond the layers above._

## Collections

### `aix` · ~320 documents → `AixBulletin`

AIX collection from IBM includes security advisories and CVEs specifically for the AIX operating system.

| field | type | description | example |
|---|---|---|---|
| `aixFileset` | `list | None` | Affected AIX filesets (fileset, product, version). | `[{"productName": "aix", "productVersions": ["…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `almalinux` · ~6k documents → `AlmalinuxBulletin`

AlmaLinux vulnerability collection includes advisories and CVEs specific to AlmaLinux OS, sourced from official security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "almalinux", "OSVersion": "8", "arch"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `alpinelinux` · ~15k documents → `AlpinelinuxBulletin`

Alpine Linux vulnerability collection includes advisories and CVEs specific to Alpine Linux OS and its packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "perl-http-body"…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Alpine Linux", "OSVersion": "any", "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `altlinux` · ~2.3k documents → `AltlinuxBulletin`

AltLinux collection provides security advisories and CVEs specifically for Alt Linux OS, detailing vulnerabilities and patches for its software packages.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ALT Linux", "OSVersion": "10", "arch…` |

### `amazon` · ~9.9k documents → `AmazonBulletin`

Amazon's vulnerability collection includes security advisories and CVEs related to AWS services and products, focusing on cloud security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "id=\"new_packag…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Amazon Linux", "OSVersion": "any", "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `archlinux` · ~1.9k documents → `ArchlinuxBulletin`

Arch Linux security advisories and CVEs related to Arch Linux packages and systems, sourced from the Arch Linux security team.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "alpm", "name": "php", "version…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Arch Linux", "OSVersion": "any", "ar…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `astralinux` · ~23k documents → `AstralinuxBulletin`

Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "linux-headers-5…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Astra Linux", "OSVersion": "1.7", "a…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `cbl_mariner` · ~17k documents → `CblMarinerBulletin`

The CBL Mariner collection includes security advisories and CVEs specific to Microsoft's CBL Mariner Linux distribution.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Azure Linux", "OSVersion": "3.0", "a…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `centos` · ~3.7k documents → `CentosBulletin`

CentOS vulnerability collection includes advisories and CVEs specific to CentOS OS, sourced from official vendor bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "CentOS", "OSVersion": "7", "arch": "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `cgr` · ~24k documents → `CgrBulletin`

CGR (Common Vulnerability Reporting) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `cloudlinux` · ~610 documents → `CloudlinuxBulletin`

CloudLinux provides security advisories and CVEs specific to CloudLinux OS, focusing on vulnerabilities affecting Linux-based web hosting environments.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "6", "arch": "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `debian` · ~15k documents → `DebianBulletin`

Debian vulnerability collection includes security advisories and CVEs specific to Debian OS packages and software components.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "13", "arch": …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `debiancve` · ~74k documents → `DebiancveBulletin`

Debian Vulnerability Database (Debian VDE) provides security advisories and CVEs for Debian OS packages and related software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "openjdk-11", "v…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "999", "arch":…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `fedora` · ~36k documents → `FedoraBulletin`

Fedora collection includes security advisories, CVEs, and patches for vulnerabilities affecting Fedora OS and its packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "rust-faster-hex…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Fedora Linux", "OSVersion": "43", "a…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `freebsd` · ~6.8k documents → `FreebsdBulletin`

FreeBSD vulnerability collection includes advisories and CVEs specific to FreeBSD operating system vulnerabilities and security updates.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "pkg", "name": "jenkins", "vers…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "FreeBSD", "OSVersion": "any", "arch"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `freebsd_advisory` · ~740 documents → `FreebsdAdvisoryBulletin`

FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories.

| field | type | description | example |
|---|---|---|---|
| `affectedVersions` | `Any` | Affected version ranges. |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `gentoo` · ~3.9k documents → `GentooBulletin`

Gentoo collection includes vulnerability advisories and CVEs specific to Gentoo Linux packages and systems.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Gentoo", "OSVersion": "any", "arch":…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `mageia` · ~6.3k documents → `MageiaBulletin`

Mageia security advisories provide information on vulnerabilities affecting Mageia Linux, including CVEs and patches for various software packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "python-pip", "v…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Mageia", "OSVersion": "10", "arch": …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `mariadbunix` · ~400 documents → `MariadbunixBulletin`

MariaDB Unix collection includes advisories and CVEs specific to Unix-based systems for the MariaDB database server.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "7", "arch": "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `unofficial_repo` | `bool | None` | Whether the fix comes from an unofficial repository. | `true` |

### `opensuse` · ~8.9k documents → `OpensuseBulletin`

OpenSUSE vulnerability collection includes advisories and CVEs related to OpenSUSE OS and its packages, sourced from the OpenSUSE security team.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `Any` | Affected OS/distribution packages (name, version, OS, arch). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `openwrt` · ~33 documents → `OpenwrtBulletin`

OpenWrt vulnerability collection includes advisories and CVEs related to OpenWrt firmware, focusing on security issues affecting routers and embedded devices.

_No fields beyond the layers above._

### `oraclelinux` · ~11k documents → `OraclelinuxBulletin`

Oracle Linux vulnerabilities collection includes advisories and CVEs specific to Oracle Linux OS, sourced from Oracle's security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "thunderbird", "…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Oracle Linux", "OSVersion": "8", "ar…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `photon` · ~4.5k documents → `PhotonBulletin`

Photon is a vulnerability collection from the National Vulnerability Database (NVD) focusing on vendor-specific advisories and CVEs related to various software products.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Photon", "OSVersion": "5.0-91", "arc…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"severity": "critical"}` |

### `redos` · ~15k documents → `RedosBulletin`

Redos collection from various security databases focuses on vulnerabilities related to Regular Expression Denial of Service (ReDoS) across multiple vendors and products, typically including advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "redos", "operator": "lt", "packageFi…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `rocky` · ~10k documents → `RockyBulletin`

Rocky Linux vulnerability collection from the Rocky Linux project includes advisories and CVEs related to Rocky Linux OS security.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "oci-seccomp-bpf…` |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Rocky Linux", "OSVersion": "10", "ar…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `fixes` | `list[str] | None` | Fix references (fixed versions / patches). | `["https://bugzilla.redhat.com/show_bug.cgi?id…` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. |  |

### `rosalinux` · ~1.4k documents → `RosalinuxBulletin`

Rosalinux collection includes security advisories and CVEs specific to the Rosalyn Linux OS, sourced from the official Rosalyn security team.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ROSA", "OSVersion": "any", "arch": "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `slackware` · ~2k documents → `SlackwareBulletin`

Slackware vulnerability collection includes advisories and CVEs specific to the Slackware Linux distribution, focusing on security issues in its packages.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Slackware", "OSVersion": "15.0", "ar…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `suse` · ~6.8k documents → `SuseBulletin`

SUSE vulnerability collection includes advisories and CVEs specific to SUSE Linux products and services, detailing security issues and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "suse", "OSVersion": "12", "arch": "x…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `susecve` · ~73k documents → `SusecveBulletin`

SUSE CVE Database: Contains advisories and CVEs related to vulnerabilities in SUSE Linux products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedPackage` | `Any` | Affected OS/distribution packages (name, version, OS, arch). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `threats` | `list | None` | Threat-intelligence entries. | `[{"category": "impact", "date": "2026-10-13T2…` |

### `ubuntu` · ~11k documents → `UbuntuBulletin`

Ubuntu vulnerability collection from the Ubuntu Security Notices, covering advisories and CVEs related to Ubuntu OS and its packages.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `Any` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "16.04", "arch…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `ubuntucve` · ~85k documents → `UbuntucveBulletin`

Ubuntu CVE database provides security advisories and CVEs specifically for Ubuntu OS vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "14.04", "arch…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `bugs` | `list[str] | None` | Linked bug-tracker entries. | `["http://bugs.debian.org/cgi-bin/bugreport.cg…` |

### `virtuozzo` · ~1.1k documents → `VirtuozzoBulletin`

Virtuozzo collection includes security advisories and CVEs related to Virtuozzo virtualization software and its components.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedPackage` | `Any` | Affected OS/distribution packages (name, version, OS, arch). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `wolfi` · ~17k documents → `WolfiBulletin`

Wolfi is a vulnerability collection from the Wolfi project, focusing on Linux OS packages, typically containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list | None` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

