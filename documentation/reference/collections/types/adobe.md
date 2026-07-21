# `adobe`  ·  ~770 documents

Adobe's vulnerability collection includes advisories and CVEs related to Adobe products, addressing security issues across various software and platforms.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48286"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@adobe.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Adobe has released updates for Adobe Experie…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48286", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://helpx.adobe.com/security/products/ex…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APSB26-74"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T17:42:07"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@adobe.co…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Adobe"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:40:05.726000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"APSB26-74 : Security update available for Ad…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"adobe"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/adobe/APSB26-74"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `22` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "26.5.0", "operator": "le", "nam…` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `adobe` collection.

_None in the sample._

