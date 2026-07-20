# `thn`  ·  ~21k documents

The "thn" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 30% | Related CVE identifiers referenced by this document. | `["CVE-2026-14266"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 25% | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}, object{score,short_description,tags}, object{short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "7-Zip XZ decoding heap…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://thehackernews.com/2026/07/new-7-zip-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THN:7462CC7CFE2DA1053C7DD1A2C73E54E8"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:18:51"` |
| `metrics` | `object{adp,cna}` | 25% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T09:10:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T09:10:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"The Hacker News"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:18:51.509000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"New 7-Zip Vulnerability Could Let Crafted XZ…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thn"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/thn/THN:7462CC7CFE2DA105…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |

