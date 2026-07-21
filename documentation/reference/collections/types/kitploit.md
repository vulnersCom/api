# `kitploit`  ·  ~6k documents

Kitploit is a security database focused on exploits and tools, primarily for penetration testing and ethical hacking, sourced from various contributors.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: tools`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KITPLOIT:4163374071362481988"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-05-11T14:31:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-05-11T12:30:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-05-11T12:30:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-05-11T14:31:08.318000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Shodan-Dorks - Dorks for Shodan; a powerful …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kitploit"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/kitploit/KITPLOIT:416337…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `785` |

### Family fields

Present in every sampled `tools`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 0.9, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.kitploit.com/2025/05/shodan-dorks…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"KitPloit"` |
| `toolHref` | `str` | Link to the associated tool/exploit. | `"https://github.com/nullfuzz-pentest/shodan-d…` |

### Collection fields

Specific to the `kitploit` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2017-12542", "CVE-2017-5689"]` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.0", "vectorString":…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-12542", "date": "2026-06-2…` |
| `metrics` | `object{adp,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"version": "2.0", "vectorS…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/nullfuzz-pentest/shodan-…` |

