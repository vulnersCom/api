# `0daydb`  ·  ~71 documents

0daydb is a vulnerability database focused on zero-day exploits, providing advisories and detailed information on vulnerabilities across various software and platforms.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"0DAYDB:B906BFDBDE502CE63C0691A9F1882E35"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-07-02T19:14:05"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-07-02T15:46:53"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-07-02T15:46:51"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-07-02T12:46:51Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"PHP-Fusion 9.03.60 - PHP Object Injection"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"0daydb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/0daydb/0DAYDB:B906BFDBDE…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `142` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |

### Collection fields

Specific to the `0daydb` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2019-12169"]` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "acInsufInfo": false, …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"PHP-Fusion version 9.03.60 suffers from a PH…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12169", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://0daydb.com/php-fusion-9-03-60-php-ob…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"0daydb.com"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"# Exploit Title: PHP-Fusion 9.03.60 - PHP Ob…` |

