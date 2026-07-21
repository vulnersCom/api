# `carbonblack`  ·  ~850 documents

Carbon Black's collection includes vendor-specific advisories, CVEs, and threat intelligence related to endpoint security products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CARBONBLACK:E25E4441A040B53F58E36EDB86493899"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-04-22T16:27:59"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2021-04-21T15:00:28"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2021-04-21T15:00:28"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-04-21T12:00:28Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"VMware Carbon Black Delivers High-Fidelity I…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"carbonblack"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/carbonblack/CARBONBLACK:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `63` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.carbonblack.com/blog/vmware-carb…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Chris Prall"` |

### Collection fields

Specific to the `carbonblack` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-26855", "CVE-2021-26857", "CVE-202…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"For the third year in a row, VMware Carbon B…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-26855", "date": "2026-06-1…` |

