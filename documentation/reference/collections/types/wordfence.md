# `wordfence`  ·  ~520 documents

Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 45% | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 45% | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"On July 17, 2026, the WordPress Security Tea…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 45% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wordfence.com/blog/2026/07/psa-w…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WORDFENCE:A70814AA347845ABF82AC8B4A9E7CB5F"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:36:54"` |
| `metrics` | `object{adp,cna}` | 45% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T23:03:48"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T23:03:48"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chloe Chamberland"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:38:26.874000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PSA: WordPress Core Patched Unauthenticated …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wordfence"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wordfence/WORDFENCE:A708…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

