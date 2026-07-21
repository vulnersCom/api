# `htbridge`  ·  ~560 documents

HTBridge provides security advisories and vulnerability assessments focused on web applications and related technologies.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HTB23302"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-24T10:45:42"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2016-10-02T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2016-06-10T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-06-09T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Multiple RCEs via CSRF in Dolibarr"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"htbridge"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/htbridge/HTB23302"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `570` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.6, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"High-Tech Bridge"` |

### Collection fields

Specific to the `htbridge` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "3.9.2", "operator": "le", "name…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2016-10400"]` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"accessComp…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"High-Tech Bridge Security Research Lab disco…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-10400", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.htbridge.com/advisory/HTB23302"` |

