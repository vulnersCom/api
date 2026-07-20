# `openbugbounty`  ·  ~1.3M documents

OpenBugBounty is a community-driven platform that catalogs security advisories and vulnerabilities reported by researchers across various vendors and products.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Following the coordinated and responsible vu…` |
| `enchantments` | `object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 0.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.openbugbounty.org/reports/4049116/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OBB:4049116"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T16:25:10"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-07-23T13:56:00"` |
| `openbugbounty` | `object{mirror,patchStatus}` | 100% | Open Bug Bounty metadata (mirror, patch status). | `{"patchStatus": "On Hold", "mirror": ""}` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-04-24T13:56:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"EzioPaglia"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-24T14:20:05.467000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"krinner.com.gr Cross Site Scripting vulnerab…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openbugbounty"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openbugbounty/OBB:4049116"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `90` |

