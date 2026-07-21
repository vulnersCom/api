# `dsquare`  ·  ~740 documents

Dsquare provides vulnerability advisories and CVEs focused on various software products and services from multiple vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"E-734"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-11-26T18:37:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2021-10-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2021-10-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-10-19T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"WordPress Asgaros Forum < 1.15.13 SQL Inject…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"dsquare"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/dsquare/E-734"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `517` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/…` |

### Collection fields

Specific to the `dsquare` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-24827"]` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"SQL Injection vulnerabilty in WordPress Asga…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.9, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-24827", "date": "2026-06-2…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Dsquare Security"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"For the exploit source code contact DSquare …` |

