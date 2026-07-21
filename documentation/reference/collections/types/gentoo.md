# `gentoo`  ·  ~3.8k documents

Gentoo collection includes vulnerability advisories and CVEs specific to Gentoo Linux packages and systems.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GLSA-202604-03"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T05:36:54"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-04-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-17T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-17T20:05:58.799000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"FUSE: Multiple Vulnerabilities"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gentoo"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/gentoo/GLSA-202604-03"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Background\n\nFUSE (Filesystem in Usersp…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |

### Collection fields

Specific to the `gentoo` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Gentoo", "OSVersion": "any", "arch":…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-33150", "CVE-2026-33179"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories",…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33150", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.gentoo.org/glsa/202604-03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |

