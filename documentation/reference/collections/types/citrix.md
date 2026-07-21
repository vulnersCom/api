# `citrix`  ·  ~5.3k documents

Citrix vulnerability collection includes advisories and CVEs related to Citrix products and services, sourced from Citrix's official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-53565", "CVE-2026-53566"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "citrix", "version": "4…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Severity - High\n\n## Description of Problem…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53565", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.citrix.com/support-home/kbse…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CTX696734"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T17:37:14"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "citrix", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T11:51:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T13:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Citrix"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:37:14.411000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Citrix Secure Access Client for Windows and …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"citrix"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/citrix/CTX696734"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "14.1-72.61", "operator": "lt", …` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `citrix` collection.

_None in the sample._

