# `tenable`  ·  ~220 documents

Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TENABLE:FFF36F44FB0788361FCEA422EF64F32F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T19:40:17"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T17:01:13"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T17:01:13"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T19:40:20.058000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"[R1] Stand-alone Security Patch Available fo…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tenable"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/tenable/TENABLE:FFF36F44…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Arnie Cabral"` |

### Collection fields

Specific to the `tenable` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-11187", "CVE-2025-15467", "CVE-202…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "openssl-security", "v…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@php.net", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"[R1] Stand-alone Security Patch Available fo…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11187", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.tenable.com/security/tns-2026-19"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "openssl-securi…` |

