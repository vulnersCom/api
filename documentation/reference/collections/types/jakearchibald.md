# `jakearchibald`  ·  ~120 documents

Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JAKEARCHIBALD:097FA566D8C7BEEB98D0851DF5C8AE8E"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-08T10:00:44"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T01:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-29T01:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-29T14:36:50.719000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"The Goldilocks customizable select height"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jakearchibald"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jakearchibald/JAKEARCHIB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}, object{score}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://jakearchibald.com/2026/goldilocks-se…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Jake Archibald's Blog"` |

### Collection fields

Specific to the `jakearchibald` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"I recently gave a talk on customizable (as i…` |

