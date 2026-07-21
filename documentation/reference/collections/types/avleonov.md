# `avleonov`  ·  ~390 documents

AVLeonov provides advisories and CVEs related to vulnerabilities in various software products, sourced from multiple vendors and security bulletins.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42897"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@paloaltonetworks…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![About Cross Site Scripting - Microsoft Exc…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-59788", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://avleonov.com/2026/07/02/i089-about-c…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AVLEONOV:5A4D4FA71C7AFD6D5C3C47E9EF85410A"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-02T21:56:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T15:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-02T15:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Alexander Leonov"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T21:56:00.959000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"About Cross Site Scripting - Microsoft Excha…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"avleonov"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/avleonov/AVLEONOV:5A4D4F…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `avleonov` collection.

_None in the sample._

