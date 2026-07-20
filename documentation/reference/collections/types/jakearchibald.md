# `jakearchibald`  ·  ~120 documents

Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"I recently gave a talk on customizable (as i…` |
| `enchantments` | `object{score,short_description,tags}, object{score}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jakearchibald.com/2026/goldilocks-se…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JAKEARCHIBALD:097FA566D8C7BEEB98D0851DF5C8AE8E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-08T10:00:44"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T01:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-29T01:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jake Archibald's Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-29T14:36:50.719000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Goldilocks customizable select height"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jakearchibald"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jakearchibald/JAKEARCHIB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

