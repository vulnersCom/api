# `hpe`  ·  ~1.1k documents

HPE collection includes security advisories and CVEs related to Hewlett Packard Enterprise products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-48989", "CVE-2025-55130", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Potential Security Impact:\nLocal: Authentic…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 2.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-48989", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.hpe.com/hpesc/public/docDisp…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HPESBNW05080"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:41:12"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"hpe"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:41:13.128000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"HPESBNW05080 rev.1 - HPE Unified OSS Console…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hpe"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hpe/HPESBNW05080"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `hpe` collection.

| field | type | description | example |
|---|---|---|---|
| `vendorCvss` | `object{vector}` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/…` |

