# `krebs`  ·  ~1.1k documents

Krebs on Security provides in-depth articles and analysis on cybersecurity threats, breaches, and vulnerabilities, focusing on various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KREBS:E337AAA92EB8EC130AF8281A694FFF0E"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T03:44:36"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T19:22:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T19:22:42"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:44:37.768000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft Patches a Record 570 Security Flaws"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"krebs"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/krebs/KREBS:E337AAA92EB8…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "uncertanity": 3.0, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://krebsonsecurity.com/2026/07/microsof…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"BrianKrebs"` |

### Collection fields

Specific to the `krebs` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50661"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Microsoft Corp.** today released software …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50661", "date": "2026-07-1…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |

