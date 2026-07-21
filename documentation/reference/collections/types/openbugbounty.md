# `openbugbounty`  ·  ~1.3M documents

OpenBugBounty is a community-driven platform that catalogs security advisories and vulnerabilities reported by researchers across various vendors and products.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Following the coordinated and responsible vu…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 0.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.openbugbounty.org/reports/4049116/"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OBB:4049116"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T16:25:10"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-07-23T13:56:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-04-24T13:56:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"EzioPaglia"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-24T14:20:05.467000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"krinner.com.gr Cross Site Scripting vulnerab…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openbugbounty"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/openbugbounty/OBB:4049116"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `90` |

### Family fields

Added by the [`BugBountyBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `openbugbounty` collection.

| field | type | description | example |
|---|---|---|---|
| `openbugbounty` | `object{mirror,patchStatus}` | Open Bug Bounty metadata (mirror, patch status). | `{"patchStatus": "On Hold", "mirror": ""}` |

