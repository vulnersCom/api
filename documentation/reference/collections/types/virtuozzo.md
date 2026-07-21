# `virtuozzo`  ·  ~1.1k documents

Virtuozzo collection includes security advisories and CVEs related to Virtuozzo virtualization software and its components.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-53359"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This update provides a security fix.\n**Vuln…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53359", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://docs.virtuozzo.com/vza/VZA-2026-018.…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VZA-2026-018"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:37:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Virtuozzo"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T12:29:35.425000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Virtuozzo Infrastructure 7.2 Hotfix 4 (7.2.0…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"virtuozzo"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/virtuozzo/VZA-2026-018"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `virtuozzo` collection.

_None in the sample._

