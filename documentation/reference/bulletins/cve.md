# `cve` family

**Model:** `CveBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: cve`.

## Family fields

Present in every `cve` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-862"]` |

## Collections

### `cve` · ~370k documents → `CveCollectionBulletin`

The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories.

| field | type | description | example |
|---|---|---|---|
| `affectedConfiguration` | `Any` | Affected configuration entries. |  |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `aiDescription` | `str | None` | AI-generated summary of the vulnerability. | `"The CVE-2026-13439 entry affects the WordPre…` |
| `assigned` | `str | None` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-05-14T11:33:18"` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cnaAffected` | `Any` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"defaultStatus": "unaffected", "product": "…` |
| `cnaCpeApplicability` | `Any` | CPE applicability as supplied by the CNA. | `[{"nodes": [{"operator": "OR", "negate": fals…` |
| `cpe` | `Any` | Affected products as CPE 2.2 URIs. |  |
| `cpe23` | `Any` | Affected products as CPE 2.3 formatted strings. |  |
| `cpeConfiguration` | `Any` | Single CPE applicability configuration. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"cnaCpeConfiguration": [{"operator": "OR", "…` |
| `exploits` | `Any` | Related exploit records. |  |
| `extraReferences` | `list | None` | Additional reference URLs beyond the primary set. | `[{"url": "https://checkmk.com/werk/16918"}]` |
| `impacts` | `list | None` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-180", "descriptions": [{"…` |
| `origin` | `str | None` | Ingestion origin/pipeline the record came through. | `"composite"` |
| `problemTypes` | `Any` | Structured problem-type/weakness records (CVE JSON 5.x). |  |
| `solutions` | `Any` | Structured remediation entries (CVE JSON 5.x). |  |
| `threatData` | `Any` | Aggregated threat-intelligence signals. |  |
| `vulnStatus` | `str | None` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |
| `webApplicability` | `Any` | Web-application applicability assessment. | `{"applicable": null, "vulnerabilities": []}` |
| `workarounds` | `Any` | Structured workaround entries when no fix is available. |  |

### `cvelist` · ~370k documents → `CvelistBulletin`

CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata.

| field | type | description | example |
|---|---|---|---|
| `assigned` | `str | None` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-05-14T11:33:18"` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cnaAffected` | `Any` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"defaultStatus": "unaffected", "product": "…` |
| `cnaCpeApplicability` | `Any` | CPE applicability as supplied by the CNA. | `[{"nodes": [{"operator": "OR", "negate": fals…` |
| `dateUpdated` | `str | None` | Source-reported last-update date. | `"2026-07-21T07:20:35"` |
| `exploits` | `Any` | Related exploit records. |  |
| `impacts` | `list | None` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-180", "descriptions": [{"…` |
| `origin` | `str | None` | Ingestion origin/pipeline the record came through. | `"cve.mitre.org"` |
| `provider` | `str | None` | Organization that produced the record (e.g. the CNA). | `"Checkmk"` |
| `solutions` | `Any` | Structured remediation entries (CVE JSON 5.x). |  |
| `workarounds` | `Any` | Structured workaround entries when no fix is available. |  |

### `nvd` · ~370k documents → `NvdBulletin`

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `origin` | `str | None` | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `source_references` | `list | None` | References with their originating source. | `[{"url": "https://wpscan.com/vulnerability/5b…` |
| `vulnStatus` | `str | None` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

### `prion` · ~210k documents → `PrionBulletin`

Prion collection includes advisories and CVEs related to vulnerabilities in software products from various vendors, focusing on security issues and exploits.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `sandboxInfo` | `Any` | Sandbox detonation information. |  |

### `vulnrichment` · ~160k documents → `VulnrichmentBulletin`

Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights.

| field | type | description | example |
|---|---|---|---|
| `adpAffected` | `Any` | Affected products as reported by an ADP (Authorized Data Publisher). |  |
| `assigned` | `str | None` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-06-16T23:01:04"` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploits` | `Any` | Related exploit records. |  |
| `impacts` | `list | None` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-18", "descriptions": [{"l…` |
| `origin` | `str | None` | Ingestion origin/pipeline the record came through. | `"cisa.gov"` |
| `provider` | `str | None` | Organization that produced the record (e.g. the CNA). | `"GitHub_M"` |
| `solutions` | `Any` | Structured remediation entries (CVE JSON 5.x). |  |
| `workarounds` | `Any` | Structured workaround entries when no fix is available. |  |

