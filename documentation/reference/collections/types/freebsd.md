# `freebsd`  ·  ~6.6k documents

FreeBSD vulnerability collection includes advisories and CVEs specific to FreeBSD operating system vulnerabilities and security updates.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42533", "CVE-2026-56434", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\n\nMailpit author reports:\n\nMailpit's SMT…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56001", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://vuxml.freebsd.org/freebsd/562ff91e-8…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"562FF91E-8407-11F1-BFDE-10FFE07F9334"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:38:31"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/axllent/mailpit/security…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FreeBSD"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:38:31.737000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Mailpit -- SMTP DATA line reader buffers ove…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/freebsd/562FF91E-8407-11…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{name,registry,versionEndExcluding,versionStartIncluding}], list[object{name,registry,versionEndExcluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "pkg", "name": "mailpit", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "FreeBSD", "OSVersion": "any", "arch"…` |

### Collection fields

Specific to the `freebsd` collection.

_None in the sample._

