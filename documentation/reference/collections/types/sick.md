# `sick`  ·  ~67 documents

The "sick" collection includes advisories and CVEs from various vendors, focusing on vulnerabilities in software products and operating systems.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-8751"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "NONE", "version": "3.…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A vulnerability was discovered in several En…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-8751", "date": "2026-07-18…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.sick.com/at/en/service-and-suppo…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SCA-2026-0009"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T11:46:10"` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T13:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T13:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Sick AG"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T11:46:10.786000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Vulnerability in several Endress+Hauser prod…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sick"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/sick/SCA-2026-0009"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `sick` collection.

_None in the sample._

