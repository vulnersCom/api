# `myhack58`  ·  ~7.6k documents

MyHack58 provides security advisories and CVEs focused on vulnerabilities related to various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MYHACK58:62202097573"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-02-01T03:40:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-03-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-03-17T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-16T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Apache Tomcat from file contains to RCE expl…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"myhack58"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/myhack58/MYHACK58:622020…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `230` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 9.6, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"\u4f5a\u540d"` |

### Collection fields

Specific to the `myhack58` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2020-1938"]` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The content of the article introduction \nTh…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-1938", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.myhack58.com/Article/html/3/62/20…` |

