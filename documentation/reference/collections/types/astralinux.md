# `astralinux`  ·  ~18k documents

Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-31419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}` | CVSS v3.x score block. | `{"cvssV3": {"source": "NONE", "version": "3.0…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In the Linux kernel, the following vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53362", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://wiki.astralinux.ru/astra-linux-se18-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASTRA:1159995680070894737113968011466307"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T04:48:36"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,nvd,vendor}, object{adp}, object{cna,vendor}, object{nvd,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T08:12:13"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-09T08:12:13"` |
| `references` | `list[str]` | External reference URLs. | `["https://wiki.astralinux.ru/astra-linux-se18…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"AstraLinux"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T18:51:17.671000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Astra Linux \u2013 Vulnerability found in Li…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"astralinux"` |
| `vendorId` | `str` | Vendor's own identifier for the advisory, when provided. | `"OVAL:ASTRA:DEF:11599956800708947371139680114…` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/astralinux/ASTRA:1159995…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding}]` | Affected libraries/packages (name, purl, version range). | `[{"name": "linux-headers-6.1.166-1", "version…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Astra Linux", "OSVersion": "1.8", "a…` |

### Collection fields

Specific to the `astralinux` collection.

_None in the sample._

