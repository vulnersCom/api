# `myhack58`  ·  ~7.6k documents

MyHack58 provides security advisories and CVEs focused on vulnerabilities related to various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 65% | Related CVE identifiers referenced by this document. | `["CVE-2020-1938"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 55% | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 55% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The content of the article introduction \nTh…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 9.6, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 65% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-1938", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.myhack58.com/Article/html/3/62/20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MYHACK58:62202097573"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-02-01T03:40:51"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-03-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-03-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"\u4f5a\u540d"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-16T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Apache Tomcat from file contains to RCE expl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"myhack58"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/myhack58/MYHACK58:622020…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `230` |

