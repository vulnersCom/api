# `duo`  ·  ~54 documents

Duo Security's collection features advisories and CVEs related to its authentication products and services, focusing on security vulnerabilities and fixes.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# Duo Product Security Advisory\n\n**Advisor…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://duo.com/labs/psa/duo-psa-2014-007"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DUO:D3F6F5E7B4015B33735F13DE1D5791B4"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-01-29T20:54:29"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2014-10-15T04:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2014-10-15T04:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Duo Security Advisories"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2014-10-15T01:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"DUO-PSA-2014-007: Duo Product Security Advis…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"duo"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/duo/DUO:D3F6F5E7B4015B33…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `28` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `duo` collection.

_None in the sample._

