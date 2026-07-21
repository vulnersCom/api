# `veeam`  ·  ~1.8k documents

Veeam collection includes advisories and CVEs related to Veeam software products, focusing on vulnerabilities affecting backup and recovery solutions.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VEEAM:KB4881"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:36:54"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T14:12:47"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:36:54.725000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Release Information for Fsas ETERNUS EP300 P…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"veeam"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/veeam/VEEAM:KB4881"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Veeam software"` |

### Collection fields

Specific to the `veeam` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "13", "operator": "eq", "name": …` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-44963"]` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "support@hackerone.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"______\n\nThis plug-in leverages the Veeam U…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44963", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.veeam.com/kb4881"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "support@hackero…` |

