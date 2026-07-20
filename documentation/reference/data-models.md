# Data models

Every document Vulners returns is a **bulletin**. The SDK models them in three layers, so you get typed fields and IDE hints at whatever level of detail you need:

1. **`Bulletin`** — the base: the fields every document carries.
2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per `bulletinFamily`, each adding that family's fields.
3. **Collection models** — one per collection `type` (see [Collections reference](collections/index.md)), adding the fields specific to that collection.

`search`/`archive`/`audit` return the most specific model that matches a document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model keeps `extra="allow"`: a field Vulners adds before the SDK models it is still there on the object, just untyped — nothing is ever dropped.

> These tables are generated from the models themselves (`dev-tools/data-models/sample_collections.py`); the field descriptions are the same ones your IDE shows on hover.

## `Bulletin` — base fields

| field | wire name | type | description |
|---|---|---|---|
| `id` | `id` | `str \| None` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). |
| `type` | `type` | `str \| None` | Source collection the document comes from (cve, exploitdb, ubuntu, …). |
| `bulletin_family` | `bulletinFamily` | `str \| None` | Broad family the document belongs to (cve, exploit, software, …). |
| `title` | `title` | `str \| None` | Human-readable title of the document. |
| `description` | `description` | `str \| None` | Full text or summary of the vulnerability/advisory. |
| `href` | `href` | `str \| None` | Canonical URL of the document at its original source. |
| `vhref` | `vhref` | `str \| None` | URL of the document on vulners.com. |
| `source_href` | `sourceHref` | `str \| None` | URL of the raw source object, when it differs from href. |
| `source_data` | `sourceData` | `str \| None` | Raw, unparsed source body as delivered by the origin. |
| `published` | `published` | `str \| None` | Original publication timestamp (ISO-8601). |
| `modified` | `modified` | `str \| None` | Last modification timestamp at the source (ISO-8601). |
| `last_seen` | `lastseen` | `str \| None` | Last time Vulners observed/refreshed the document (ISO-8601). |
| `timestamps` | `timestamps` | `Timestamps \| None` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). |
| `cvss` | `cvss` | `Cvss \| None` | Primary CVSS score block (version, base score, vector, severity, source). |
| `cvss2` | `cvss2` | `Cvss \| None` | CVSS v2 score block. |
| `cvss3` | `cvss3` | `Cvss \| None` | CVSS v3.x score block. |
| `cvss4` | `cvss4` | `Cvss \| None` | CVSS v4.0 score block. |
| `epss` | `epss` | `list[EpssScore] \| None` | EPSS exploitation-probability forecast datapoints (score + percentile). |
| `metrics` | `metrics` | `Any \| None` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). |
| `cvelist` | `cvelist` | `list[str] \| None` | Related CVE identifiers referenced by this document. |
| `references` | `references` | `list[str] \| None` | External reference URLs. |
| `reporter` | `reporter` | `str \| None` | Person or organization credited with reporting/authoring it. |
| `source_available` | `sourceAvailable` | `bool \| None` | Whether the raw source data is available for this document. |
| `vendor_id` | `vendorId` | `str \| None` | Vendor's own identifier for the advisory, when provided. |
| `view_count` | `viewCount` | `int \| None` | How many times the document has been viewed on Vulners. |
| `enchantments` | `enchantments` | `Enchantments \| None` | Vulners-computed enrichment layer (AI score, tags, related docs). |
| `attachments` | `attachments` | `list[Any] \| None` | Binary/media attachments associated with the document. |
| `immutable_fields` | `immutableFields` | `list[str] \| None` | Fields the source marks as immutable. |

## Family models

### `CveBulletin`  (extends `Bulletin`)

``bulletinFamily: cve`` (or ``NVD``) — a CVE record and its scoring/enrichment.

`bulletinFamily`: `cve`, `NVD`

| field | wire name | description |
|---|---|---|
| `affected_configuration` | `affectedConfiguration` | Affected configuration entries. |
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `ai_description` | `aiDescription` | AI-generated summary of the vulnerability. |
| `cna_affected` | `cnaAffected` | Affected products as reported by the CNA (CVE JSON 5.x). |
| `cpe` | `cpe` | Affected products as CPE 2.2 URIs. |
| `cpe23` | `cpe23` | Affected products as CPE 2.3 formatted strings. |
| `cpe_configurations` | `cpeConfigurations` | CPE applicability configurations (NVD-style match tree). |
| `cwe` | `cwe` | Associated CWE weakness identifiers. |
| `exploits` | `exploits` | Related exploit records. |
| `problem_types` | `problemTypes` | Structured problem-type/weakness records (CVE JSON 5.x). |
| `solutions` | `solutions` | Structured remediation entries (CVE JSON 5.x). |
| `vuln_status` | `vulnStatus` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). |
| `web_applicability` | `webApplicability` | Web-application applicability assessment. |
| `workarounds` | `workarounds` | Structured workaround entries when no fix is available. |

### `ExploitBulletin`  (extends `Bulletin`)

``bulletinFamily: exploit`` — exploit code / PoC and its provenance.

`bulletinFamily`: `exploit`

| field | wire name | description |
|---|---|---|
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `exploit_type` | `exploitType` | Type of exploit (remote, local, webapps, …). |
| `has_poc` | `has_poc` | Whether a proof-of-concept is available. |
| `osvdbidlist` | `osvdbidlist` | Legacy OSVDB identifiers. |
| `verified` | `verified` | Whether the exploit/finding was verified. |

### `ScannerBulletin`  (extends `Bulletin`)

``bulletinFamily: scanner`` — a vulnerability-scanner plugin (Nessus, OpenVAS, …).

`bulletinFamily`: `scanner`

| field | wire name | description |
|---|---|---|
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `cpe` | `cpe` | Affected products as CPE 2.2 URIs. |
| `cvss_score_source` | `cvssScoreSource` | Which party/standard the CVSS score was taken from. |
| `exploit_available` | `exploitAvailable` | Whether a public exploit is available. |
| `nasl_family` | `naslFamily` | Nessus NASL plugin family. |
| `nessus_severity` | `nessusSeverity` | Severity as rated by the Nessus scanner. |
| `plugin_id` | `pluginID` | Scanner plugin identifier (e.g. Nessus plugin id). |
| `solution` | `solution` | Recommended remediation/fix, as text. |

### `SoftwareBulletin`  (extends `AdvisoryBulletin`)

``bulletinFamily: software`` — an OS/vendor package or product advisory.

`bulletinFamily`: `software`

| field | wire name | description |
|---|---|---|
| `affected_package` | `affectedPackage` | Affected OS/distribution packages (name, version, OS, arch). |
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `cpe_configurations` | `cpeConfigurations` | CPE applicability configurations (NVD-style match tree). |
| `cwe` | `cwe` | Associated CWE weakness identifiers. |
| `severity` | `severity` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). |
| `solution` | `solution` | Recommended remediation/fix, as text. |

### `UnixBulletin`  (extends `Bulletin`)

``bulletinFamily: unix`` — a Linux/Unix distribution package advisory.

`bulletinFamily`: `unix`

| field | wire name | description |
|---|---|---|
| `affected_libraries` | `affectedLibraries` | Affected libraries/packages (name, purl, version range). |
| `affected_package` | `affectedPackage` | Affected OS/distribution packages (name, version, OS, arch). |
| `affected_versions` | `affectedVersions` | Affected version ranges. |
| `bugs` | `bugs` | Linked bug-tracker entries. |
| `cwe` | `cwe` | Associated CWE weakness identifiers. |
| `fixes` | `fixes` | Fix references (fixed versions / patches). |

### `InfoBulletin`  (extends `Bulletin`)

``bulletinFamily: info`` — threat intel, advisories and news write-ups

`bulletinFamily`: `info`

| field | wire name | description |
|---|---|---|
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `cwe` | `cwe` | Associated CWE weakness identifiers. |
| `known_ransomware_campaign_use` | `knownRansomwareCampaignUse` | Whether it is known to be used in ransomware campaigns. |
| `severity` | `severity` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). |
| `tags` | `tags` | Classification tags applied to the document. |
| `wild_exploited` | `wildExploited` | Whether the vulnerability is exploited in the wild. |

### `LibraryBulletin`  (extends `Bulletin`)

``bulletinFamily: library`` — a package-ecosystem advisory (OSV, Snyk).

`bulletinFamily`: `library`

| field | wire name | description |
|---|---|---|
| `affected_libraries` | `affectedLibraries` | Affected libraries/packages (name, purl, version range). |
| `osv_affected` | `osvAffected` | OSV 'affected' ranges. |
| `purls` | `purls` | Affected packages as Package-URL (purl) strings. |
| `withdrawn` | `withdrawn` | Withdrawal date if the advisory was retracted. |

### `MicrosoftBulletin`  (extends `Bulletin`)

``bulletinFamily: microsoft`` — an MSRC/KB/update advisory.

`bulletinFamily`: `microsoft`

| field | wire name | description |
|---|---|---|
| `kb` | `kb` | Microsoft Knowledge Base article id. |
| `kb_list` | `kbList` | Microsoft KB article ids covered by the update. |
| `ms_platform` | `msplatform` | Affected Microsoft platform. |
| `ms_severity` | `msseverity` | Microsoft's severity rating for the advisory. |
| `parentseeds` | `parentseeds` | Updates that supersede this update. |
| `superseeds` | `superseeds` | Updates this update supersedes. |

### `BugBountyBulletin`  (extends `Bulletin`)

``bulletinFamily: bugbounty`` — a bug-bounty / disclosure report.

`bulletinFamily`: `bugbounty`

| field | wire name | description |
|---|---|---|
| `bounty` | `bounty` | Bounty amount/details paid for the report. |
| `bounty_state` | `bountyState` | State of the bounty (awarded, pending, …). |
| `cwe_id` | `cwe_id` | Single associated CWE identifier. |
| `repository` | `repository` | Source code repository associated with the report. |

### `AdvisoryBulletin`  (extends `Bulletin`)

Vendor/CERT advisory shape (blog, cnnvd, cnvd, crypto, euvd, jvn, ncsc,

`bulletinFamily`: `blog`, `cnnvd`, `cnvd`, `crypto`, `euvd`, `jvn`, `ncsc`, `nozomi`, `tools`

| field | wire name | description |
|---|---|---|
| `affected_software` | `affectedSoftware` | Affected software products (name/version/operator). |
| `cpe_configurations` | `cpeConfigurations` | CPE applicability configurations (NVD-style match tree). |

