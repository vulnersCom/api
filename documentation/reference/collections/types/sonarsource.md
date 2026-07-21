# `sonarsource`  ·  ~38 documents

SonarSource provides security advisories and vulnerability data for various programming languages and frameworks, focusing on code quality and security issues.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONARSOURCE:D0C5296C81770997D6DB807F2C38F1F0"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-03-01T15:30:19"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-03-01T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-03-01T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-28T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"5 things to consider in performance comparis…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonarsource"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/sonarsource/SONARSOURCE:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `17` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{backreferences,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.5, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.sonarsource.com/5-things-to-con…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"SonarSource"` |

### Collection fields

Specific to the `sonarsource` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-46088", "CVE-2022-23131", "CVE-202…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![A woman running a performance comparison t…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-46088", "date": "2026-06-1…` |

