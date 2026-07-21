# `modx`  ·  ~22 documents

MODX vulnerability collection includes advisories and CVEs related to the MODX CMS, focusing on security issues affecting its core and plugins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"<p>This is a sub-categrory of Announcements …` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://community.modx.com/t/about-the-secur…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MODX:D0DA7C02EA4F77438E2AD4AA9259E056"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-11-11T03:46:45"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-02-14T19:53:55"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-02-14T19:53:55"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"smashingred"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-02-14T16:53:55Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"About the Security Notices category"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"modx"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/modx/MODX:D0DA7C02EA4F77…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `122` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "2.6.4", "name…` |

### Collection fields

Specific to the `modx` collection.

_None in the sample._

