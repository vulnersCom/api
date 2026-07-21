# `rdot`  ·  ~230 documents

Rdot is a vulnerability collection from the Rdot database, focusing on advisories and CVEs related to various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\u0412\u0441\u0435\u043c \u043f\u0440\u0438\…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://rdot.org/forum/showthread.php?t=4958"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RDOT:4958"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-02-09T00:35:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-02-07T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-02-07T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Zecurion"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-02-06T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"\u041f\u0440\u0438\u0433\u043b\u0430\u0448\u…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rdot"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rdot/RDOT:4958"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `30` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `rdot` collection.

_None in the sample._

