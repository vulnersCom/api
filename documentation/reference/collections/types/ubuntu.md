# `ubuntu`  ·  ~11k documents

Ubuntu vulnerability collection from the Ubuntu Security Notices, covering advisories and CVEs related to Ubuntu OS and its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"USN-8558-1"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T03:36:52"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T22:36:08"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T22:36:08"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T03:36:52.186000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"USN-8558-1: ImageMagick vulnerabilities"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ubuntu"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ubuntu/USN-8558-1"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"It was discovered that ImageMagick did not l…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Ubuntu"` |

### Collection fields

Specific to the `ubuntu` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{EvaluationStatus,OS,OSExtraInfo,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}], list[object{EvaluationStatus,OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "14.04", "arch…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-33905", "CVE-2026-33900", "CVE-202…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://ubuntu.com/security/notices/USN-8558-1"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://launchpad.net/bugs/2161362"]` |

