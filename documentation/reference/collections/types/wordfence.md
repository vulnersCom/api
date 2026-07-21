# `wordfence`  ·  ~520 documents

Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WORDFENCE:9A0D6E9704F05C17C1F775BF9C9B5C8E"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T00:10:46"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T21:49:19"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T21:49:19"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T00:10:47.565000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"wp2shell Aftermath: The First Critical Unaut…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wordfence"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wordfence/WORDFENCE:9A0D…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 0.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Alex Thomas"` |

### Collection fields

Specific to the `wordfence` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"On Friday, July 17, 2026, the WordPress Secu…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wordfence.com/blog/2026/07/wp2sh…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |

