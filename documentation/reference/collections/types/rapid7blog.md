# `rapid7blog`  ·  ~1.7k documents

Rapid7 Blog provides insights on security vulnerabilities, advisories, and exploit techniques relevant to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Overview\n\nOn July 17, 2026, a GitHub Se…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.rapid7.com/blog/post/etr-cve-202…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7BLOG:20F3692F768CBC3939DA6DEE73C29ECC"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:38:32"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T22:23:03"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T22:23:03"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Rapid7 Labs"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:36:54.236000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-63030: wp2shell a Critical Remote C…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7blog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rapid7blog/RAPID7BLOG:20…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `rapid7blog` collection.

_None in the sample._

