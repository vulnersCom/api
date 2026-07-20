# `coresecurity`  ·  ~250 documents

Core Security provides vulnerability advisories and CVEs focused on various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-24121"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## 1\\. Advisory Information \n\n**Title:** …` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.2, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-24121", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.coresecurity.com/advisories/logi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CORE-2022-0001"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-07T14:08:39"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Core Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-01-31T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unified Office Total Connect Now\u2120 Cooki…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coresecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/coresecurity/CORE-2022-0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `43` |

