# `carbonblack`  ·  ~850 documents

Carbon Black's collection includes vendor-specific advisories, CVEs, and threat intelligence related to endpoint security products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 5% | Related CVE identifiers referenced by this document. | `["CVE-2021-26855", "CVE-2021-26857", "CVE-202…` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 5% | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 5% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"For the third year in a row, VMware Carbon B…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-26855", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.carbonblack.com/blog/vmware-carb…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CARBONBLACK:E25E4441A040B53F58E36EDB86493899"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-04-22T16:27:59"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-04-21T15:00:28"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-04-21T15:00:28"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chris Prall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-04-21T12:00:28Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VMware Carbon Black Delivers High-Fidelity I…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"carbonblack"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/carbonblack/CARBONBLACK:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `63` |

