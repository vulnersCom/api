# `alpinelinux`  ·  ~13k documents

Alpine Linux vulnerability collection includes advisories and CVEs specific to Alpine Linux OS and its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-53583"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This candidate has been reserved by an organ…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"dependencies": {"references": [{"type": "cv…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14741", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.alpinelinux.org/vuln/CVE-20…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALPINE:CVE-2026-53583"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:40:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"adp": {"ssvc": {"id": "CVE-2026-14741", "ro…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:35:53"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-19T17:35:53"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/squid-cache/squid/commit…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Alpine Linux Development Team"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:40:00.517000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-53583"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"alpinelinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/alpinelinux/ALPINE:CVE-2…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndIncluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "libgit2", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Alpine Linux", "OSVersion": "any", "…` |

### Collection fields

Specific to the `alpinelinux` collection.

_None in the sample._

