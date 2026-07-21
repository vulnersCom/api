# `thn`  ·  ~21k documents

The "thn" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-14266"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}, object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "7-Zip XZ decoding heap…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://thehackernews.com/2026/07/new-7-zip-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THN:7462CC7CFE2DA1053C7DD1A2C73E54E8"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:18:51"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T09:10:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T09:10:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"The Hacker News"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:18:51.509000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"New 7-Zip Vulnerability Could Let Crafted XZ…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thn"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/thn/THN:7462CC7CFE2DA105…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `thn` collection.

_None in the sample._

