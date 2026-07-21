# `ubuntucve`  ·  ~72k documents

Ubuntu CVE database provides security advisories and CVEs specifically for Ubuntu OS vulnerabilities.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-54572"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Rclone is a command-line program to sync fil…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-54572", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://ubuntu.com/security/CVE-2026-54572"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"UB:CVE-2026-54572"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T14:56:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T10:55:55"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T22:17:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-5…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ubuntu.com"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T14:56:36.068000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-54572"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ubuntucve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ubuntucve/UB:CVE-2026-54…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{EvaluationStatus,OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "18.04", "arch…` |

### Collection fields

Specific to the `ubuntucve` collection.

_None in the sample._

