# `coalfire`  ·  ~600 documents

Coalfire provides security advisories and vulnerability reports focused on various vendors and products, primarily for compliance and risk management.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"COALFIRE:A3A400ED82636541769021632F5593B0"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-06T21:53:03"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-02-06T16:23:35"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-02-06T16:23:35"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-02-06T13:23:35Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Privacy information management system consid…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coalfire"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/coalfire/COALFIRE:A3A400…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `17` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.8, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.coalfire.com/the-coalfire-blog/p…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"The Coalfire Blog"` |

### Collection fields

Specific to the `coalfire` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Organizations that want to pursue ISO 42001 …` |

