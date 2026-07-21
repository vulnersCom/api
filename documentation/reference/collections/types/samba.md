# `samba`  ·  ~170 documents

Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAMBA:"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-27T19:48:40"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-26T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-08T05:56:41.139000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Missing access checks on reparse point"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"samba"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/samba/SAMBA:"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Samba Security"` |

### Collection fields

Specific to the `samba` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-3012"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Description\n\nStarting with Samba 4.21, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-3012", "date": "2026-07-01…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.samba.org/samba/security/CVE-202…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

