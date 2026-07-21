# `nodejsblog`  ·  ~78 documents

Node.js Blog: A collection from various sources focusing on Node.js vulnerabilities, including advisories, CVEs, and security best practices.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48615", "CVE-2026-48617", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Thursday, June 18, 2026 Security Releases\n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48615", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://nodejs.org/en/blog/vulnerability/jun…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NODEJSBLOG:JUNE-2026-SECURITY-RELEASES"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T06:05:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-18T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-18T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OpenJS Foundation"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T18:05:00.753000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Thursday, June 18, 2026 Security Releases"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nodejsblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nodejsblog/NODEJSBLOG:JU…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `207` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `nodejsblog` collection.

_None in the sample._

