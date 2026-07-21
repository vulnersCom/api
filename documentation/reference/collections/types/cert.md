# `cert`  ·  ~3.7k documents

A collection of advisories and alerts from the Computer Emergency Response Team (CERT) covering various vendors and products, including CVEs and security incidents.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-44909", "CVE-2026-59173", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Overview\n\nA denial-of-service (DoS) vu…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59173", "date": "2026-07-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.kb.cert.org/vuls/id/885548"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VU:885548"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:27:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://datatracker.ietf.org/doc/rfc9113/"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CERT"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T20:37:02.980000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Denial-of-service vulnerability in HTTP/2 se…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cert"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cert/VU:885548"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `cert` collection.

_None in the sample._

