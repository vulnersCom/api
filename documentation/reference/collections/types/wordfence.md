# `wordfence`  ·  ~520 documents

Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"On July 17, 2026, the WordPress Security Tea…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wordfence.com/blog/2026/07/psa-w…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WORDFENCE:A70814AA347845ABF82AC8B4A9E7CB5F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:36:54"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T23:03:48"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T23:03:48"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Chloe Chamberland"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:38:26.874000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"PSA: WordPress Core Patched Unauthenticated …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wordfence"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wordfence/WORDFENCE:A708…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `wordfence` collection.

_None in the sample._

