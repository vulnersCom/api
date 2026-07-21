# `canvas`  ·  ~620 documents

Canvas is a vulnerability database focused on educational software, providing advisories, CVEs, and security updates for the Canvas LMS platform.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2020-0796"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Name**\|  smbghost_lpe  \n---\|---  \n**CVE*…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-0796", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://exploitlist.immunityinc.com/home/expl…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SMBGHOST_LPE"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:33:14"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-03-12T16:15:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-03-12T16:15:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Immunity Canvas"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-12T13:15:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Immunity Canvas: SMBGHOST_LPE"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"canvas"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/canvas/SMBGHOST_LPE"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `209` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `canvas` collection.

_None in the sample._

