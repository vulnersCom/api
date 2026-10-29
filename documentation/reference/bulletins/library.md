# `library` family

**Model:** `LibraryBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: library`.

## Family fields

Present in every `library` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

## Collections

### `osv_alba` · ~980 documents → `OsvAlbaBulletin`

OSV-ALBA is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source software with advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "coreutils", "ve…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["almalinux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "AlmaLinux:8", "name": "coreut…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/almalinux/coreutils?distro=almalinu…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_alea` · ~220 documents → `OsvAleaBulletin`

OSV-Alea aggregates vulnerability data from various sources, focusing on open-source software projects and providing advisories, CVEs, and exploit information.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "java-17-openjdk…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["almalinux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "AlmaLinux:8", "name": "java-1…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/almalinux/java-17-openjdk?distro=al…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_alpine` · ~4.8k documents → `OsvAlpineBulletin`

OSV Alpine is a vulnerability database focused on Alpine Linux, providing advisories and CVEs related to security issues in Alpine packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "libxi", "versio…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["alpine"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Alpine:v3.24", "name": "libxi…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:apk/alpine/libxi?distro=alpine-3.24"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_alsa` · ~5.1k documents → `OsvAlsaBulletin`

OSV-ALS is a vulnerability collection from the Open Source Vulnerability Database focusing on advisories and CVEs related to the ALSA sound system.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "webkit2gtk3", "…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["almalinux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "related", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "AlmaLinux:8", "name": "webkit…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/almalinux/webkit2gtk3?distro=almali…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_asb` · ~2.7k documents → `OsvAsbBulletin`

OSV ASB provides advisories and CVEs from various vendors, focusing on open-source vulnerabilities across multiple products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["android"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["A-5223735…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Android", "name": "platform/p…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_azl` · ~20k documents → `OsvAzlBulletin`

OSV-AZL provides vulnerability advisories and CVEs specifically for Azure services and products, sourced from the Open Source Vulnerability database.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["azure linux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Azure Linux:3", "name": "kern…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_bell` · ~22k documents → `OsvBellBulletin`

OSV-Bell provides advisories and CVEs related to open-source vulnerabilities, focusing on various software projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["alpaquita"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Alpaquita:stream", "name": "l…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `str | None` | Withdrawal date if the advisory was retracted. | `"2026-10-29T06:34:53.699000Z"` |

### `osv_bit` · ~10k documents → `OsvBitBulletin`

OSV Bit provides vulnerability data sourced from the Open Source Vulnerability database, focusing on open-source projects and typically includes advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["bitnami"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Bitnami", "name": "parse", "p…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_can` · ~5 documents → `OsvCanBulletin`

The osv_can collection from the Open Source Vulnerability Database includes advisories and CVEs related to open-source software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["gsd"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "GSD", "name": "openssl"}]` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `str | None` | Withdrawal date if the advisory was retracted. | `"2023-03-14T07:04:18.321000Z"` |

### `osv_cga` · ~1.3M documents → `OsvCgaBulletin`

OSV-CGA is a collection from the Open Source Vulnerability Database focusing on advisories and CVEs related to open-source software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["chainguard"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2025…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Chainguard", "name": "eco-nod…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.0/AV:L/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_cleanstart` · ~13k documents → `OsvCleanstartBulletin`

OSV Clean Start is a vulnerability database that aggregates CVEs and advisories focused on open-source projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["cleanstart"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2025…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "CleanStart", "name": "valkey"…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_clsa` · ~22k documents → `OsvClsaBulletin`

OSV-CLSA provides vulnerability advisories and CVEs from various vendors and products, focusing on security issues across multiple software ecosystems.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["tuxcare"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2023…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "TuxCare:npm", "name": "zod", …` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_curl` · ~240 documents → `OsvCurlBulletin`

OSV database for cURL vulnerabilities, including advisories and CVEs related to the cURL software library.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `Any` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). |  |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). |  |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_cve` · ~250k documents → `OsvCveBulletin`

OSV-CVE is a vulnerability database that aggregates CVE advisories across various vendors and products, providing detailed vulnerability information.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `Any` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). |  |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["GHSA-83rm…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). |  |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_debian` · ~61k documents → `OsvDebianBulletin`

OSV Debian provides security advisories and CVEs specifically for Debian OS vulnerabilities, sourced from the Debian security team.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "qpid-proton", "…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["debian"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Debian:12", "name": "qpid-pro…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/debian/qpid-proton@0.37.0-2?distro=…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_dla` · ~4.7k documents → `OsvDlaBulletin`

OSV DLA provides vulnerability advisories and CVEs for various open-source projects, sourced from the Open Source Vulnerability Database.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "netty", "versio…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["debian"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2024…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Debian:11", "name": "netty", …` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/debian/netty?distro=debian-11"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_drupal` · ~800 documents → `OsvDrupalBulletin`

OSV database for Drupal vulnerabilities, including advisories and CVEs related to Drupal core and contributed modules.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "composer", "name": "drupal/med…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["packagist"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Packagist:https://packages.dr…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:composer/drupal/media_alias_display", "…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_dsa` · ~6.3k documents → `OsvDsaBulletin`

OSV-DSA provides security advisories and CVEs for various open-source projects, focusing on vulnerabilities affecting specific software packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "lxd", "versionE…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["debian"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Debian:12", "name": "lxd", "p…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/debian/lxd?distro=debian-12", "pkg:…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_dtsa` · ~210 documents → `OsvDtsaBulletin`

OSV DTSA is a data source providing advisories and CVEs focused on vulnerabilities across various open-source software projects.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "mediawiki", "ve…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["debian"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2011…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Debian:6.0", "name": "mediawi…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/debian/mediawiki?distro=debian-6.0"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_echo` · ~12k documents → `OsvEchoBulletin`

OSV Echo is a vulnerability database that aggregates advisories and CVEs across various open-source projects and libraries.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["echo"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["TEMP-000…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Echo", "name": "c-ares", "pur…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_eef` · ~380 documents → `OsvEefBulletin`

The osv_eef collection from the Open Source Vulnerability Database includes advisories and CVEs related to open-source software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["hex"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Hex", "name": "bandit", "purl…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_ghsa` · ~37k documents → `OsvGhsaBulletin`

OSV GHSA is a vulnerability collection from GitHub that includes advisories and CVEs related to security issues in open-source software projects.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "pypi", "name": "tornado", "ver…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["pypi"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "PyPI", "name": "tornado", "pu…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:pypi/tornado@0.2", "pkg:pypi/tornado@1.…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_go` · ~4.7k documents → `OsvGoBulletin`

OSV Go is a vulnerability database sourced from the Open Source Vulnerability (OSV) database, focusing on Go language packages and typically includes CVEs and advisories.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "golang", "name": "golang.org/x…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["go"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Go", "name": "golang.org/x/ne…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:golang/golang.org/x/net"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_gsd` · ~14k documents → `OsvGsdBulletin`

OSV GSD provides vulnerability advisories and CVEs from various vendors, focusing on open-source software security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["linux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Linux", "name": "Kernel"}]` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_hsec` · ~36 documents → `OsvHsecBulletin`

OSV HSEC is a vulnerability database focusing on open-source software, providing advisories and CVEs related to security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "hackage", "name": "jwt", "vers…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["hackage"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Hackage", "name": "jwt", "pur…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:hackage/jwt"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_jlsec` · ~1.7k documents → `OsvJlsecBulletin`

OSV.jlsec provides security advisories and CVEs specifically for Julia packages, focusing on vulnerabilities affecting the Julia programming environment.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["julia"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Julia", "name": "xapian_jll",…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_lsn` · ~56 documents → `OsvLsnBulletin`

OSV-LSN is a collection from the Open Source Vulnerability database focusing on vulnerabilities in open-source software, typically containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "deb", "name": "linux", "versio…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["ubuntu"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2023…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Ubuntu:Pro:16.04:LTS", "name"…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/ubuntu/linux@6.17.0-5.5?distro=ubun…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_mal` · ~240k documents → `OsvMalBulletin`

OSV-MAL is a vulnerability collection from the Open Source Vulnerability (OSV) database, focusing on malware-related advisories and CVEs across various software products.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "npm", "name": "dsh-redteam-mod…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["npm"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["GHSA-r4m9…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "npm", "name": "dsh-redteam-mo…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:npm/dsh-redteam-mode@0.15.2"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_mgasa` · ~6.3k documents → `OsvMgasaBulletin`

OSV MGASA provides security advisories and CVEs for various software products and operating systems, sourced from the Mageia community.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "python-pip", "v…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["mageia"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Mageia:10", "name": "python3"…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/mageia/python-pip?distro=mageia-10"…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_mini` · ~190k documents → `OsvMiniBulletin`

OSV Mini is a vulnerability data source providing concise advisories and CVEs focused on open-source projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "datadog-agent-c…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["minimos"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "MinimOS", "name": "datadog-ag…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:apk/minimos/datadog-agent-core-integrat…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_oesa` · ~9.2k documents → `OsvOesaBulletin`

OSV OESA provides advisories and CVEs related to open-source vulnerabilities, focusing on various open-source projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "golang", "versi…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["openeuler"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "openEuler:22.03-LTS-SP4", "na…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/openeuler/golang?distro=openeuler-2…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_opensuse` · ~13k documents → `OsvOpensuseBulletin`

OpenSUSE vulnerability data from OSV includes advisories and CVEs related to OpenSUSE products and their security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "k3sup", "versio…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["opensuse"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "related", "references": ["CVE-2024-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "openSUSE:Tumbleweed", "name":…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/opensuse/k3sup?distro=opensuse-tumb…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_osec` · ~35 documents → `OsvOsecBulletin`

OSV OSEC provides security advisories and CVEs related to open-source software vulnerabilities across various projects and ecosystems.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["opam"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "opam", "name": "ocaml", "purl…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_osv` · ~4.5k documents → `OsvOsvBulletin`

OSV (Open Source Vulnerability) database provides vendor-agnostic advisories and CVEs for open-source software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["oss-fuzz"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "OSS-Fuzz", "name": "ndpi", "p…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_psf` · ~200 documents → `OsvPsfBulletin`

OSV-PSF is a vulnerability collection from the Open Source Vulnerability Database focusing on Python Software Foundation projects, including advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `Any` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). |  |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["CVE-2026-…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). |  |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_pub` · ~1.3k documents → `OsvPubBulletin`

OSV.Pub is a vulnerability database that aggregates advisories and CVEs across various open-source projects and ecosystems.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["android"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["A-4979730…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Android", "name": ":unknown:"}]` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_pysec` · ~8k documents → `OsvPysecBulletin`

OSV Python Security (osv_pysec) provides advisories and CVEs related to vulnerabilities in Python packages, sourced from the Open Source Vulnerability (OSV) database.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "pypi", "name": "brotlicffi", "…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["pypi"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["BIT-node-…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "PyPI", "name": "brotlicffi", …` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:pypi/brotlicffi@0.8.0", "pkg:pypi/brotl…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rhba` · ~350 documents → `OsvRhbaBulletin`

Red Hat Bugzilla advisories (RHBA) provide security updates and CVEs for Red Hat products, focusing on vulnerabilities and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "cockpit", "vers…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["red hat"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Red Hat:enterprise_linux:10.2…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/redhat/cockpit?distro=rhel-10.2", "…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rhea` · ~97 documents → `OsvRheaBulletin`

OSV Rhea aggregates vulnerability advisories and CVEs from various sources, focusing on open-source software projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "flightctl", "ve…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["red hat"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "related", "references": ["GO-2026-4…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Red Hat:edge_manager:1.1::el1…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/redhat/flightctl?distro=rhel-9", "p…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rhlw` · ~230 documents → `OsvRhlwBulletin`

OSV_RHLW is a collection from the Open Source Vulnerability database focusing on Red Hat Linux vulnerabilities, typically containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["red hat lightwell"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2025…` |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Red Hat Lightwell:Maven", "na…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rhsa` · ~24k documents → `OsvRhsaBulletin`

Red Hat Security Advisories (RHSA) provide security updates and advisories for Red Hat products, including CVEs and mitigation guidance.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "rust-sequoia-sq…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["red hat"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Red Hat:enterprise_linux:10.2…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/redhat/rust-sequoia-sq?distro=rhel-…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rlsa` · ~4.6k documents → `OsvRlsaBulletin`

OSV-RLSA is a vulnerability collection from the Open Source Vulnerability Database, focusing on advisories and CVEs related to open-source software.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "libreswan", "ve…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["rocky linux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Rocky Linux:10", "name": "lib…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/rocky/libreswan?distro=rocky-10"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_root` · ~21k documents → `OsvRootBulletin`

OSV Root is a vulnerability database that provides advisories and CVEs focused on open-source software projects and their dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["root"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Root:Go", "name": "golang.org…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rsec` · ~14 documents → `OsvRsecBulletin`

OSV-RSEC is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source projects and containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "cran", "name": "png", "version…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["cran"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "CRAN", "name": "png", "purl":…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:cran/png"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rustsec` · ~1.3k documents → `OsvRustsecBulletin`

The osv_rustsec collection from the RustSec database provides security advisories and CVEs specifically for Rust programming language packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "cargo", "name": "cargo-nextest…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["crates.io"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "aliases", "references": ["GHSA-vc25…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "crates.io", "name": "cargo-ne…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:cargo/cargo-nextest"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_rxsa` · ~29 documents → `OsvRxsaBulletin`

OSV (Open Source Vulnerability) database collection focusing on open source software vulnerabilities, typically containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "kernel", "versi…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["rocky linux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Rocky Linux:9", "name": "kern…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/rocky/kernel?distro=rocky-9"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_suse` · ~24k documents → `OsvSuseBulletin`

OSV SUSE provides security advisories and CVEs specific to SUSE products, aiding in vulnerability assessment for SUSE operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "containerd", "v…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["suse"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "related", "references": ["CVE-2026-…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "SUSE:Linux Enterprise Server …` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/suse/containerd?distro=sles-12.5"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_ubuntu` · ~65k documents → `OsvUbuntuBulletin`

OSV database for Ubuntu, covering security advisories and CVEs related to Ubuntu OS and its packages.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["ubuntu"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2026…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Ubuntu:Pro:14.04:LTS", "name"…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "Ubuntu", "score": "medium"}]` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/ubuntu/linux@3.11.0-12.19?distro=ub…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_usn` · ~8.3k documents → `OsvUsnBulletin`

OSV USN is a collection from the Open Source Vulnerability database focusing on advisories for Ubuntu OS vulnerabilities and associated CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["ubuntu"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "related", "references": ["UBUNTU-CV…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Ubuntu:Pro:16.04:LTS", "name"…` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:deb/ubuntu/brotli@0.2.0+dfsg-1?distro=u…` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `osv_uvi` · ~2.4k documents → `OsvUviBulletin`

OSV UVI is a vulnerability collection from the Open Source Vulnerability Database, focusing on open-source projects and containing advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `list[str] | None` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). | `["linux"]` |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Linux", "name": "Kernel"}]` |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `str | None` | Withdrawal date if the advisory was retracted. | `"2023-03-14T07:04:18.315000Z"` |

### `osv_v8` · ~1 documents → `OsvV8Bulletin`

OSV v8 is a vulnerability database from the Open Source Vulnerability (OSV) project, covering advisories and CVEs for open-source software projects.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `ecosystems` | `Any` | Package ecosystems the advisory applies to (npm, pypi, go, crates.io, rubygems, alpine, debian, …). |  |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `Any` | OSV cross-references to other advisories. |  |
| `osvPackages` | `Any` | OSV package records (ecosystem, name, purl). |  |
| `osvSeverity` | `Any` | OSV severity entries (score, type). |  |
| `purls` | `Any` | Affected packages as Package-URL (purl) strings. |  |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `snyk` · ~54k documents → `SnykBulletin`

Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "npm", "name": "@iobandamwer/na…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `snykData` | `Any` | Snyk-specific data (exploit maturity, malicious flag). | `{"socialTrendAlert": false, "proprietary": fa…` |

### `vulnersosv` · ~370k documents → `VulnersosvBulletin`

Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them.

| field | type | description | example |
|---|---|---|---|
| `baseAffectedLibrary` | `Any` | The primary affected library (name, purl, version range). | `{"registry": "pypi", "name": "vllm", "version…` |
| `snapshot_date` | `str | None` | Date of the data snapshot this record was taken from. | `"2026-10-26"` |
| `transitiveAffectedLibraries` | `Any` | Libraries affected transitively via dependencies. | `[{"registry": "pypi", "name": "aana", "versio…` |

