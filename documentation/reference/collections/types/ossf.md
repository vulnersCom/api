# `ossf`  ·  ~230k documents

OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSF:MAL-2026-10965"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:39:30"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T04:35:40"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T04:35:40"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:39:30.338000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Malicious code in requestor-util (npm)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossf"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ossf/OSSF:MAL-2026-10965"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OSSF Malicious Packages"` |

### Collection fields

Specific to the `ossf` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\n---\n_-= Per source details. Do not edit b…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/ossf/malicious-packages/b…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/advisories/GHSA-m3c7-2j3…` |
| `vendorId` | `str` | Vendor's own identifier for the advisory, when provided. | `"MAL-2026-10965"` |

