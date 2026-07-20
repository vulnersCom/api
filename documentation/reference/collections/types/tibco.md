# `tibco`  ·  ~220 documents

TIBCO collection includes security advisories and CVEs related to TIBCO software products, focusing on vulnerabilities affecting their applications and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 55% | Affected software products (name/version/operator). | `[{"version": "5.16.1", "operator": "eq", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 55% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-11548"]` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 15% | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 45% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 25% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@tibco.com", "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**ibi WebFOCUS - Unauthenticated RCE Vulnera…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 70% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11548", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://community.tibco.com/advisories/ibi-s…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TIBCO:IBI-WEBFOCUS-CVE-2025-11548"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-22T21:28:13"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 55% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@tibco.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-10-14T16:18:02"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-10-14T16:18:02"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cloud Software Group, Inc."` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-10-14T21:51:08.162000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ibi Security Advisory: October 14, 2025 - ib…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tibco"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/tibco/TIBCO:IBI-WEBFOCUS…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

