# `checkpoint_advisories`  ·  ~14k documents

Checkpoint Advisories provide security bulletins from Check Point Software Technologies, including advisories and CVEs for their products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-21490"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 4.0, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A remote code execution vulnerability exists…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-21490", "date": "2026-06-1…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CPAI-2022-0853"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-11-28T14:45:52"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-11-28T00:00:00"` |
| `protected_by` | `list[str]` | 100% | Products/controls that protect against the issue. | `["Security Gateway R81", "Security Gateway R8…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-11-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Check Point Advisories"` |
| `severity` | `str` | 100% | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"Medium"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-11-27T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Oracle MySQL Cluster Remote Code Execution (…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"checkpoint_advisories"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/checkpoint_advisories/CP…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |
| `vulnerable_products` | `list[str]` | 100% | Product identifiers known to be vulnerable. | `["Oracle MySQL Cluster 7.4.35 and prior", "Or…` |

