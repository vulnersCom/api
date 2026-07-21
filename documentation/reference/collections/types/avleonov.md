# `avleonov`  ·  ~390 documents

AVLeonov provides advisories and CVEs related to vulnerabilities in various software products, sourced from multiple vendors and security bulletins.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AVLEONOV:CA02075B6F584DF1326FA59B5029634F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T19:36:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T14:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T14:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T19:36:50.913000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"July \"In the Trend of VM\" (#29): Microsoft…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"avleonov"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/avleonov/AVLEONOV:CA0207…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://avleonov.com/2026/07/20/i104-july-in…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Alexander Leonov"` |

### Collection fields

Specific to the `avleonov` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42897"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@paloaltonetworks…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![July In the Trend of VM \\(#29\\): Microso…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-59788", "date": "2026-07-2…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

