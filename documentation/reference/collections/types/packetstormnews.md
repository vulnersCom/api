# `packetstormnews`  ·  ~6.9k documents

Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-14440"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cna", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@cloudflare.com", "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"GNUnet is a peer-to-peer framework with focu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/213585/"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORMNEWS:213585"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-08T07:35:00"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cna", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-12-29T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-12-29T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Christian Grothoff"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/213585"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T07:35:00.709000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"GNUnet P2P Framework 0.26.2"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstormnews"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/packetstormnews/PACKETST…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `369` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `packetstormnews` collection.

_None in the sample._

