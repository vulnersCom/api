# `googleprojectzero`  ·  ~250 documents

Google Project Zero collection features advisories and CVEs focused on vulnerabilities in various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-54957"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Posted by Seth Jenkins\n\nWe recently publis…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-54957", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://projectzero.google/2026/05/pixel-10-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GOOGLEPROJECTZERO:6829A4B13E4B1C7ABB1562D1BB…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-14T03:14:58"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-13T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-13T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"GoogleProjectZero"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T03:14:58.783000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"A 0-click exploit chain for the Pixel 10: Wh…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"googleprojectzero"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/googleprojectzero/GOOGLE…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `40` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `googleprojectzero` collection.

_None in the sample._

