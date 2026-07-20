# `mmpc`  ·  ~730 documents

MMPC is a Microsoft Malware Protection Center collection focusing on Microsoft products, providing advisories, CVEs, and malware threat intelligence.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 15% | Related CVE identifiers referenced by this document. | `["CVE-2023-6448"]` |
| `cvss` | `object{score,severity,vector,version}, object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 10% | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{attackComplexity,attackVector,availabilityImpact,baseScore,baseSeverity,confidentialityImpact,integrityImpact,privilegesRequired,scope,userInteraction,vectorString,version}, object{cvssV3,exploitabilityScore,impactScore}, object{cvssV3}` | 15% | CVSS v3.x score block. | `{"version": "3.1", "vectorString": "CVSS:3.1/…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Since late 2023, Microsoft has observed an i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.7, "uncertanity": 0.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 15% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-6448", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/security/blo…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MMPC:D41D8CD98F00B204E9800998ECF8427E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-06-20T19:17:49"` |
| `metrics` | `object{adp,cna,nvd}` | 5% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-05-30T17:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-05-30T17:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft Threat Intelligence"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-05-30T14:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Exposed and vulnerable: Recent attacks highl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mmpc"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mmpc/MMPC:D41D8CD98F00B2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `89` |

