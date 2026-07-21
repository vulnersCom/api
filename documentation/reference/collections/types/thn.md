# `thn`  ·  ~21k documents

The "thn" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THN:1695B0439D466F36F288C6BDB01EE6AD"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T18:35:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T18:23:03"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T18:23:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T18:35:32.720000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"FakeGit Campaign Uses 7,600 GitHub Repositor…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thn"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/thn/THN:1695B0439D466F36…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 1.5, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"The Hacker News"` |

### Collection fields

Specific to the `thn` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-33053"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://thehackernews.com/2026/07/fakegit-ca…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |

