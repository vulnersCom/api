# `qt`  ·  ~41 documents

Qt vulnerabilities from the Qt Company, covering advisories and CVEs related to the Qt framework across various platforms and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"QT:B48ED91285C0207980E4D3AF7DB01E1A"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-12-04T03:22:18"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-12-03T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-12-03T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-12-03T20:42:27.230000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security advisory: Improper validation of ta…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"qt"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/qt/QT:B48ED91285C0207980…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `15` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Tuukka Kettunen"` |

### Collection fields

Specific to the `qt` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-12385"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "a59d8014-47c4-4630-ab4…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Improper Validation of Specified Quantity in…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-12385", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.qt.io/blog/security-advisory-imp…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "a59d8014-47c4-4…` |

