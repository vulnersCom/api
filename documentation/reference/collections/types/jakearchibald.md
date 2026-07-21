# `jakearchibald`  ·  ~120 documents

Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"I recently gave a talk on customizable (as i…` |
| `enchantments` | `object{score,short_description,tags}, object{score}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://jakearchibald.com/2026/goldilocks-se…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JAKEARCHIBALD:097FA566D8C7BEEB98D0851DF5C8AE8E"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-08T10:00:44"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T01:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-29T01:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Jake Archibald's Blog"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-29T14:36:50.719000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"The Goldilocks customizable select height"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jakearchibald"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jakearchibald/JAKEARCHIB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `jakearchibald` collection.

_None in the sample._

