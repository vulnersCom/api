# `huawei`  ·  ~1k documents

Huawei's collection includes security advisories and CVEs related to Huawei products and software vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HUAWEI-SA-20250325-01-PC-EN"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T10:37:34"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-03-26T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-03-26T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-26T04:33:43Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Security Advisory - Authentication Bypass Vu…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huawei"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/huawei/HUAWEI-SA-2025032…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `81` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Huawei Technologies"` |

### Collection fields

Specific to the `huawei` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "YutuFZ-5651S1", "operator": "eq…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-52972"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@huawei.com", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Huawei PCs have a vulnerability that allows …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-52972", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.huawei.com/en/psirt/security-adv…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@huawei.c…` |

