# `adobe`  ·  ~770 documents

Adobe's vulnerability collection includes advisories and CVEs related to Adobe products, addressing security issues across various software and platforms.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 90% | Affected software products (name/version/operator). | `[{"version": "26.5.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | 90% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 5% | Related CVE identifiers referenced by this document. | `["CVE-2026-48286"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 5% | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@adobe.com", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Adobe has released updates for Adobe Experie…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48286", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://helpx.adobe.com/security/products/ex…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APSB26-74"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T17:42:07"` |
| `metrics` | `object{adp,cna}` | 5% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@adobe.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Adobe"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:40:05.726000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"APSB26-74 : Security update available for Ad…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"adobe"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/adobe/APSB26-74"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `22` |

