# `sonarsource`  ·  ~38 documents

SonarSource provides security advisories and vulnerability data for various programming languages and frameworks, focusing on code quality and security issues.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 50% | Related CVE identifiers referenced by this document. | `["CVE-2021-46088", "CVE-2022-23131", "CVE-202…` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 40% | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 40% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![A woman running a performance comparison t…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{backreferences,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.5, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 50% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-46088", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.sonarsource.com/5-things-to-con…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONARSOURCE:D0C5296C81770997D6DB807F2C38F1F0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-03-01T15:30:19"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-03-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-03-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SonarSource"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-28T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"5 things to consider in performance comparis…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonarsource"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sonarsource/SONARSOURCE:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

