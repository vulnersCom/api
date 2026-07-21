# `wizblog`  ·  ~650 documents

Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Part 3: How the Red Agent bypassed a credit …` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wiz.io/blog/red-agent-pov-busine…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIZBLOG:DE537C472999F083DEFF7BACB77EEC15"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T15:36:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T13:33:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T13:33:42"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Gal Nagli"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T15:36:53.962000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"The Red Agent POV: The One Boolean That Brok…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wizblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wizblog/WIZBLOG:DE537C47…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `wizblog` collection.

_None in the sample._

