# `rdot`  ·  ~230 documents

Rdot is a vulnerability collection from the Rdot database, focusing on advisories and CVEs related to various software products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\u0412\u0441\u0435\u043c \u043f\u0440\u0438\…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rdot.org/forum/showthread.php?t=4958"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RDOT:4958"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-02-09T00:35:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-02-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-02-07T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Zecurion"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-02-06T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\u041f\u0440\u0438\u0433\u043b\u0430\u0448\u…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rdot"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rdot/RDOT:4958"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `30` |

