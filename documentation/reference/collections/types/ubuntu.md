# `ubuntu`  ·  ~11k documents

Ubuntu vulnerability collection from the Ubuntu Security Notices, covering advisories and CVEs related to Ubuntu OS and its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-43341", "CVE-2026-31669", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Several security issues were discovered in t…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-43341", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://ubuntu.com/security/notices/USN-8490-2"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"USN-8490-2"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:36:52"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T10:10:48"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T10:10:48"` |
| `references` | `list[str]` | External reference URLs. | `["https://launchpad.net/bugs/2160650"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Ubuntu"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T09:36:58.735000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"USN-8490-2: Linux kernel (Real-time) vulnera…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ubuntu"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ubuntu/USN-8490-2"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{EvaluationStatus,OS,OSExtraInfo,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}], list[object{EvaluationStatus,OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "24.04", "arch…` |

### Collection fields

Specific to the `ubuntu` collection.

_None in the sample._

