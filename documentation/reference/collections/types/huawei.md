# `huawei`  ·  ~1k documents

Huawei's collection includes security advisories and CVEs related to Huawei products and software vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "YutuFZ-5651S1", "operator": "eq…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-52972"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@huawei.com", "v…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Huawei PCs have a vulnerability that allows …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-52972", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.huawei.com/en/psirt/security-adv…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HUAWEI-SA-20250325-01-PC-EN"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T10:37:34"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@huawei.c…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-03-26T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-03-26T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Huawei Technologies"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-26T04:33:43Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory - Authentication Bypass Vu…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huawei"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/huawei/HUAWEI-SA-2025032…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `81` |

