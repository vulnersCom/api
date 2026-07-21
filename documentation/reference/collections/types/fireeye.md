# `fireeye`  ·  ~540 documents

FireEye collection includes vendor-specific advisories and CVEs related to cybersecurity threats and exploits for various products and services.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-31207", "CVE-2021-34473", "CVE-202…` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Since our initial public release of capa, in…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-31207", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.fireeye.com/blog/threat-research…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FIREEYE:A7220068AE8525CC3BBB5F13CD1C2492"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-09-15T13:48:34"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2021-09-15T13:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2021-09-15T13:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/fireeye/capa", "https://…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FireEye"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-09-15T10:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"ELFant in the Room \u2013 capa v3"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fireeye"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/fireeye/FIREEYE:A7220068…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `39` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `fireeye` collection.

_None in the sample._

