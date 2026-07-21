# `xssed`  ·  ~31k documents

XSSed is a vulnerability database focused on cross-site scripting (XSS) vulnerabilities, providing advisories and exploit details for various web applications.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Security researcher 0x73F, has submitted on …` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.xssed.com/mirror/81499/"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"XSSED:81499"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2016-03-20T00:54:31"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2015-03-13T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2015-12-03T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["http://lavillette.com"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"0x73F"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-12-02T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Unfixed XSS vulnerability at lavillette.com"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"xssed"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/xssed/XSSED:81499"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `64` |

### Family fields

Added by the [`BugBountyBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `xssed` collection.

_None in the sample._

