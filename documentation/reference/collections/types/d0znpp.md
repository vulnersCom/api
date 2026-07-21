# `d0znpp`  ·  ~140 documents

The d0znpp collection provides vendor-specific advisories and CVEs related to vulnerabilities in various software products from the d0znpp database.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"D0ZNPP:0C2FCF0287AEFF54B886B3013D571884"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-04T08:13:23"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2023-05-14T06:55:29"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2023-05-14T06:55:29"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-14T03:55:29Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"The Hand-y Etiquette of Modern All-Remote Cu…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"d0znpp"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/d0znpp/D0ZNPP:0C2FCF0287…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `25` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.7, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://d0znpp.medium.com/the-hand-y-etiquet…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Ivan Novikov"` |

### Collection fields

Specific to the `d0znpp` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In today\u2019s fast-paced digital world, re…` |

