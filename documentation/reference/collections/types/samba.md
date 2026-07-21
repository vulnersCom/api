# `samba`  ·  ~170 documents

Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-4408"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Description\n\nSamba file servers and cla…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-4408", "date": "2026-06-24…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.samba.org/samba/security/CVE-202…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAMBA:CVE-2026-4408"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T15:49:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-26T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Samba Security"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-27T19:48:40.832000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Unauthenticated Remote Code Execution"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"samba"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/samba/SAMBA:CVE-2026-4408"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `samba` collection.

_None in the sample._

