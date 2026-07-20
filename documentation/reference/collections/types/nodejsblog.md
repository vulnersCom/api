# `nodejsblog`  ·  ~78 documents

Node.js Blog: A collection from various sources focusing on Node.js vulnerabilities, including advisories, CVEs, and security best practices.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 85% | Related CVE identifiers referenced by this document. | `["CVE-2026-48615", "CVE-2026-48617", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 80% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Thursday, June 18, 2026 Security Releases\n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 85% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48615", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://nodejs.org/en/blog/vulnerability/jun…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NODEJSBLOG:JUNE-2026-SECURITY-RELEASES"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T06:05:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 80% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-18T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-18T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenJS Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T18:05:00.753000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Thursday, June 18, 2026 Security Releases"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nodejsblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nodejsblog/NODEJSBLOG:JU…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `207` |

