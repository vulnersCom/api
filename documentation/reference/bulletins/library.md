# `library` family

**Model:** `LibraryBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: library`. 3 collections.

## Family fields

Present in every `library` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

## Collections

### `osv` · ~940k documents → `OsvBulletin`

OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "webkit2gtk3", "…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `osvAffected` | `Any` | OSV 'affected' ranges. |  |
| `osvCrossReferences` | `list | None` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["CVE-2024…` |
| `osvPackages` | `list | None` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Rocky Linux:8", "name": "webk…` |
| `osvSeverity` | `list | None` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:rpm/rocky/webkit2gtk3?distro=rocky-8"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `snyk` · ~36k documents → `SnykBulletin`

Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "gem", "name": "zztargettest185…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `snykData` | `Any` | Snyk-specific data (exploit maturity, malicious flag). | `{"socialTrendAlert": false, "proprietary": fa…` |

### `vulnersosv` · ~27k documents → `VulnersosvBulletin`

Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them.

| field | type | description | example |
|---|---|---|---|
| `baseAffectedLibrary` | `Any` | The primary affected library (name, purl, version range). | `{"name": "dev.sigstore:sigstore-java", "versi…` |
| `snapshot_date` | `str | None` | Date of the data snapshot this record was taken from. | `"2026-06-23"` |
| `transitiveAffectedLibraries` | `Any` | Libraries affected transitively via dependencies. | `[{"name": "dev.sigstore:sigstore-maven-plugin…` |

