# `tenable`  ·  ~220 documents

Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-11187", "CVE-2025-13034", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "vulnreport@tenable.com…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11187", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.tenable.com/security/tns-2026-18"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TENABLE:629066FB944DD92B1B80C9706A10934B"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:37:25"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T21:30:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T21:30:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Aaron Roy"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:37:25.953000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tenable"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/tenable/TENABLE:629066FB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `17` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `tenable` collection.

_None in the sample._

