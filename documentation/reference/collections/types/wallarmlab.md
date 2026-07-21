# `wallarmlab`  ·  ~550 documents

Wallarm Lab provides security advisories and CVEs focused on web application vulnerabilities across various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"_Editor's note: This article was originally …` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://lab.wallarm.com/clearing-up-the-term…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WALLARMLAB:F205C6FCD2CFCEAC7B97D09EA6187C01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T21:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-13T21:18:13"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-13T21:18:13"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Tim Erlin"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-13T21:36:51.376000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"AI Control Platform vs. AI Firewall vs. AI G…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wallarmlab"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wallarmlab/WALLARMLAB:F2…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `wallarmlab` collection.

_None in the sample._

