# `coresecurity`  ·  ~250 documents

Core Security provides vulnerability advisories and CVEs focused on various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-24121"]` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## 1\\. Advisory Information \n\n**Title:** …` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.2, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-24121", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.coresecurity.com/advisories/logi…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CORE-2022-0001"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-07T14:08:39"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-02-01T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-02-01T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Core Security"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-01-31T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Unified Office Total Connect Now\u2120 Cooki…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coresecurity"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/coresecurity/CORE-2022-0…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `43` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `coresecurity` collection.

_None in the sample._

