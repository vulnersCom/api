# `threatpost`  ·  ~16k documents

Threatpost provides security news and analysis, focusing on vulnerabilities, exploits, and advisories across various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THREATPOST:671939D0AFDC28B6E98676767DE43622"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T14:41:47"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-08-31T12:57:48"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-08-31T12:57:48"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-08-31T09:57:48Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Student Loan Breach Exposes 2.5M Records"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"threatpost"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/threatpost/THREATPOST:67…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `125` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nate Nelson"` |

### Collection fields

Specific to the `threatpost` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-36260"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\n\nEdFinancial and the Oklahoma Student Loa…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-36260", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://threatpost.com/student-loan-breach-e…` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `references` | `list[str]` | External reference URLs. | `["https://apps.web.maine.gov/online/aeviewer/…` |

