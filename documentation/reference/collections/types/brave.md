# `brave`  ·  ~58 documents

Brave collection includes vulnerability advisories and CVEs specific to the Brave browser, sourced from security bulletins and vendor updates.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BRAVE-DESKTOP-1.91.168"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-05T07:10:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-03T05:18:53"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-03T05:18:53"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-05T07:10:32.630000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Brave Desktop 1.91.168 Security Fixes"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"brave"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/brave/BRAVE-DESKTOP-1.91…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `24` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Brave Software"` |

### Collection fields

Specific to the `brave` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.91.168", "operator": "lt", "n…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"- Added the ability to disable or delay auto…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/brave/brave-browser/relea…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/brave/brave-browser/issu…` |

