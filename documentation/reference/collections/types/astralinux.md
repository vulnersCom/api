# `astralinux`  ·  ~18k documents

Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASTRA:1160153519839032895845406354003523"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T04:57:00"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T08:12:13"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-09T08:12:13"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T18:58:57.383000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Astra Linux \u2013 Vulnerability found in Li…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"astralinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/astralinux/ASTRA:1160153…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In the Linux kernel, the following vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"AstraLinux"` |

### Collection fields

Specific to the `astralinux` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding}]` | Affected libraries/packages (name, purl, version range). | `[{"name": "linux-headers-6.1.166-1", "version…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Astra Linux", "OSVersion": "1.8", "a…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-23239"]` |
| `cvss3` | `object{cvssV3,cvssV31}` | CVSS v3.x score block. | `{"cvssV3": {"source": "NONE", "version": "3.0…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53362", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://wiki.astralinux.ru/astra-linux-se18-…` |
| `metrics` | `object{adp,cna,vendor}, object{adp,nvd,vendor}, object{cna,vendor}, object{nvd,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `references` | `list[str]` | External reference URLs. | `["https://wiki.astralinux.ru/astra-linux-se18…` |
| `vendorId` | `str` | Vendor's own identifier for the advisory, when provided. | `"OVAL:ASTRA:DEF:11601535198390328958454063540…` |

