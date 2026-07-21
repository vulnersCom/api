# `lenovo`  ·  ~1.2k documents

Lenovo's vulnerability collection includes advisories and CVEs related to Lenovo products and software, sourced from their security bulletins.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"No description provided"` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.lenovo.com/us/en/product_sec…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"LENOVO:PS500844-NOSID"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T18:49:10"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T19:11:03"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T19:05:47"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Lenovo"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T18:49:11.070000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"NVIDIA Networking Vulnerabilities - Lenovo S…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"lenovo"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/lenovo/LENOVO:PS500844-N…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `lenovo` collection.

_None in the sample._

