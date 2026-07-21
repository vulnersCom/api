# `schneier`  ·  ~3k documents

Schneier's collection provides security advisories and analyses focused on various vulnerabilities across software and systems, sourced from Bruce Schneier's insights.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Lots of articles about this.\n\nAs usual, yo…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.schneier.com/blog/archives/2026/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SCHNEIER:76E7539B789382D6B0A8B5E807B65F60"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:36:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T21:01:37"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T21:01:37"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Bruce Schneier"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:36:50.490000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Friday Squid Blogging: Squid Washing Up on C…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"schneier"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/schneier/SCHNEIER:76E753…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `schneier` collection.

_None in the sample._

