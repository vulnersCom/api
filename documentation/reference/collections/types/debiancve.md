# `debiancve`  ·  ~60k documents

Debian Vulnerability Database (Debian VDE) provides security advisories and CVEs for Debian OS packages and related software vulnerabilities.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DEBIANCVE:CVE-2026-61861"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T15:37:44"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-11T13:01:09"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-11T13:01:09"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-11T23:37:52.349000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-61861"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"debiancve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/debiancve/DEBIANCVE:CVE-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"ImageMagick before 7.1.2-26 contains a use-a…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Debian Security Bug Tracker"` |

### Collection fields

Specific to the `debiancve` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding}], list[object{distro,name,purl,registry,versionEndIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"name": "imagemagick", "versionEndExcluding…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "14", "arch": …` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-61861"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-61861", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security-tracker.debian.org/tracker/…` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |

