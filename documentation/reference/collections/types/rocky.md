# `rocky`  ·  ~9.4k documents

Rocky Linux vulnerability collection from the Rocky Linux project includes advisories and CVEs related to Rocky Linux OS security.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RLSA-2026:41948"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T20:42:09"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T18:01:02"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T18:01:02"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T20:42:09.937000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"javapackages-tools:201801 security update"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rocky"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rocky/RLSA-2026:41948"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An update is available for module.javacc-mav…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Rockylinux Product Errata"` |

### Collection fields

Specific to the `rocky` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "ant", "versionS…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Rocky Linux", "OSVersion": "8", "arc…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-67030"]` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14544", "date": "2026-07-1…` |
| `fixes` | `list[str]` | Fix references (fixed versions / patches). | `["https://bugzilla.redhat.com/show_bug.cgi?id…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://errata.rockylinux.org/RLSA-2026:41948"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

