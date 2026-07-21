# `appercut`  ·  ~22 documents

Appercut provides security advisories and CVEs related to vulnerabilities in various software applications and platforms.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Several vulnerabilities were discovered in S…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.9, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://infowatch.com/products/attack_killer"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APPERCUT:22"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T19:12:23"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2016-08-18T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2016-08-15T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.silverstripe.org/download"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"InfoWatch APPERCUT"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-08-14T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Silver Stripe CMS: source code security anal…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"appercut"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/appercut/APPERCUT:22"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `566` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.4.1", "name…` |

### Collection fields

Specific to the `appercut` collection.

| field | type | description | example |
|---|---|---|---|
| `appercut` | `object{reportPages}` | AppercutScanner tool provenance (report pages). | `{"reportPages": [{"vulnerabilities": [{"apper…` |

