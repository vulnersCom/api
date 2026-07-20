# `tenable`  ·  ~220 documents

Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 10% | Related CVE identifiers referenced by this document. | `["CVE-2025-11187", "CVE-2025-13034", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "vulnreport@tenable.com…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11187", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.tenable.com/security/tns-2026-18"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TENABLE:629066FB944DD92B1B80C9706A10934B"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:37:25"` |
| `metrics` | `object{adp,cna,nvd}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T21:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T21:30:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Aaron Roy"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:37:25.953000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tenable"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/tenable/TENABLE:629066FB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

