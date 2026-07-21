# `tibco`  ·  ~220 documents

TIBCO collection includes security advisories and CVEs related to TIBCO software products, focusing on vulnerabilities affecting their applications and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TIBCO:IBI-WEBFOCUS-CVE-2025-11548"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-22T21:28:13"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-10-14T16:18:02"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-10-14T16:18:02"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-10-14T21:51:08.162000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"ibi Security Advisory: October 14, 2025 - ib…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tibco"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/tibco/TIBCO:IBI-WEBFOCUS…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `18` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 1.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cloud Software Group, Inc."` |

### Collection fields

Specific to the `tibco` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "5.16.1", "operator": "eq", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-11548"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@tibco.com", "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**ibi WebFOCUS - Unauthenticated RCE Vulnera…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11548", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://community.tibco.com/advisories/ibi-s…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@tibco.…` |

