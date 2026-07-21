# `hpe`  ·  ~1.1k documents

HPE collection includes security advisories and CVEs related to Hewlett Packard Enterprise products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HPESBNW05082"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T15:41:45"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T15:41:45.695000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"HPESBNW05082 rev.1 - HPE Telco Automated Ass…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hpe"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hpe/HPESBNW05082"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.7, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 0.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"hpe"` |

### Collection fields

Specific to the `hpe` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-69419", "CVE-2026-35554"]` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Potential Security Impact:\nLocal: Compromis…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-48989", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.hpe.com/hpesc/public/docDisp…` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `vendorCvss` | `object{vector}` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/…` |

