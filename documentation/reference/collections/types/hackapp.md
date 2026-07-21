# `hackapp`  ·  ~24k documents

HackApp is a vulnerability database focused on mobile applications, providing advisories, CVEs, and exploit information relevant to app security.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKAPP:COM.COINBASE.ANDROID.APK"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T18:51:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2018-03-28T20:14:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2018-03-28T20:14:42"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-03-28T17:14:42Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Coinbase - Buy Bitcoin & more. Secure Wallet…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackapp"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hackapp/HACKAPP:COM.COIN…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `688` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.0, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Hackapp.org"` |

### Collection fields

Specific to the `hackapp` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "Varies with d…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"HackApp vulnerability scanner discovered tha…` |
| `hackapp` | `object{apk,bugs,icon,link,name,release,store,vendor,version}` | HackApp mobile-app scan provenance. | `{"apk": "COM.COINBASE.ANDROID.APK", "bugs": […` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://hackapp.com/report/be556ac4576d8d5c2…` |
| `references` | `list[str]` | External reference URLs. | `["https://play.google.com/store/apps/details?…` |

