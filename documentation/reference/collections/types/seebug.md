# `seebug`  ·  ~57k documents

Seebug is a vulnerability database focused on security advisories and exploits for various software products and systems, primarily sourced from community contributions.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 80% | Related CVE identifiers referenced by this document. | `["CVE-2021-26086"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 25% | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 25% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 45% | Full text or summary of the vulnerability/advisory. | `"# Fortinet FortiWeb OS Command Injection\n\n…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 2.3, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 80% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-26086", "date": "2026-06-1…` |
| `has_poc` | `bool` | 100% | Whether a proof-of-concept is available. | `true` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.seebug.org/vuldb/ssvid-99336"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SSV:99336"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-08-20T07:29:10"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-08-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-08-20T00:00:00"` |
| `reporter` | `str` | 95% | Person or organization credited with reporting/authoring it. | `"Knownsec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `status` | `str` | 100% | Workflow status of the record. | `"cve"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-08-19T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Atlassian Jira \u6587\u4ef6\u8bfb\u53d6\u6f0…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"seebug"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/seebug/SSV:99336"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `834` |

