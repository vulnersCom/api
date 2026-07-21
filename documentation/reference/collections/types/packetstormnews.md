# `packetstormnews`  ·  ~6.9k documents

Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORMNEWS:213585"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-08T07:35:00"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-12-29T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-12-29T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T07:35:00.709000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"GNUnet P2P Framework 0.26.2"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstormnews"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/packetstormnews/PACKETST…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `372` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Christian Grothoff"` |

### Collection fields

Specific to the `packetstormnews` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"GNUnet is a peer-to-peer framework with focu…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/213585/"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/213585"` |

