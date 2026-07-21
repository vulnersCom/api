# `ics`  ·  ~4.3k documents

This collection from the ICS-CERT includes advisories and CVEs related to vulnerabilities in industrial control systems across various vendors.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VA-26-197-01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T13:36:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:56:28"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T18:56:28"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T13:36:53.257000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"remorses/genql code injection"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ics"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ics/VA-26-197-01"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.1, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Industrial Control Systems Cyber Emergency R…` |

### Collection fields

Specific to the `ics` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63397"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## 1. RISK EVALUATION\n\nremorses/genql befo…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63397", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://raw.githubusercontent.com/cisagov/CS…` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://raw.githubusercontent.com/cisagov/C…` |

