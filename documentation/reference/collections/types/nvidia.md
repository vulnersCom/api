# `nvidia`  ·  ~260 documents

NVIDIA collection includes security advisories and CVEs related to NVIDIA products and drivers, focusing on vulnerabilities affecting their software and hardware.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVIDIA:5840"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T05:37:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T11:43:36.313000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security Bulletin: NVIDIA TensorRT-LLM - Jul…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvidia"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nvidia/NVIDIA:5840"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.4, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nvidia"` |

### Collection fields

Specific to the `nvidia` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "0.0", "operator": "lt", "name":…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-24220", "CVE-2026-24226", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@nvidia.com", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"NVIDIA has released a software update for NV…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-24220", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://nvidia.custhelp.com/app/answers/deta…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@nvidia.c…` |

