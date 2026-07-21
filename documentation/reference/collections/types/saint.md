# `saint`  ·  ~4.3k documents

SAINT provides vulnerability advisories and CVEs focused on various software products and operating systems, sourced from multiple security vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-8037"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Added: 07/02/2026  \nCVE: CVE-2026-8037  \n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-8037", "date": "2026-07-15…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://download.saintcorporation.com/cgi-bi…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAINT:B94055400BC099146F61734DD1B7933A"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T20:16:52"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"SAINT Corporation"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T07:56:39.754000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Progress LoadMaster API command injection"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"saint"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/saint/SAINT:B94055400BC0…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `16` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `saint` collection.

_None in the sample._

