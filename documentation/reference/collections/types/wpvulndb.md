# `wpvulndb`  ·  ~15k documents

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPVDB-ID:73310D64-E790-4A78-AB0A-12995B762DBA"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T14:18:20"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T14:18:20.783000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"WordPress < 7.0.2 - REST API batch-route con…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpvulndb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wpvulndb/WPVDB-ID:73310D…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.5, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"wpvulndb"` |

### Collection fields

Specific to the `wpvulndb` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Description WordPress 6.9.x before 6.9.5 and…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-9185", "date": "2026-06-16…` |
| `generation` | `int` | Internal generation/version counter of the record. | `0` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://wpscan.com/vulnerability/73310d64-e7…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `references` | `list[str]` | External reference URLs. | `["https://wordpress.org/news/2026/07/wordpres…` |

