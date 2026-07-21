# `ossf`  ·  ~230k documents

OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\n---\n_-= Per source details. Do not edit b…` |
| `enchantments` | `object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Malicious PyPI package…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/ossf/malicious-packages/b…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSF:MAL-2026-10868"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:38:36"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:06:19"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:19"` |
| `references` | `list[str]` | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OSSF Malicious Packages"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:38:36.901000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Malicious code in neroteam-v1 (PyPI)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossf"` |
| `vendorId` | `str` | Vendor's own identifier for the advisory, when provided. | `"MAL-2026-10868"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ossf/OSSF:MAL-2026-10868"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `ossf` collection.

_None in the sample._

