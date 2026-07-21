# `msvr`  ·  ~46 documents

MSVR is a Microsoft vulnerability database focusing on vendor-specific advisories and CVEs related to Microsoft products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2013-1173"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 6.6, "vector": "AV:LOCAL/AC:MEDIUM/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"accessComp…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"#### Executive Summary\n\nMicrosoft is provi…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2013-1173", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://technet.microsoft.com/en-us/library/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSVR13-008"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T18:51:25"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2013-06-18T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2013-06-18T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft Vulnerability Research"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2013-06-17T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Cisco Security Service IPC Message Heap Corr…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msvr"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/msvr/MSVR13-008"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `660` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.1.00495", "…` |

### Collection fields

Specific to the `msvr` collection.

_None in the sample._

