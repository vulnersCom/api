# `fireeye`  ·  ~540 documents

FireEye collection includes vendor-specific advisories and CVEs related to cybersecurity threats and exploits for various products and services.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 40% | Related CVE identifiers referenced by this document. | `["CVE-2021-31207", "CVE-2021-34473", "CVE-202…` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 35% | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 35% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Since our initial public release of capa, in…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-31207", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.fireeye.com/blog/threat-research…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FIREEYE:A7220068AE8525CC3BBB5F13CD1C2492"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-09-15T13:48:34"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-09-15T13:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-09-15T13:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/fireeye/capa", "https://…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FireEye"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-09-15T10:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ELFant in the Room \u2013 capa v3"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fireeye"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fireeye/FIREEYE:A7220068…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

