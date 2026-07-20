# `d0znpp`  ·  ~140 documents

The d0znpp collection provides vendor-specific advisories and CVEs related to vulnerabilities in various software products from the d0znpp database.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In today\u2019s fast-paced digital world, re…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.7, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://d0znpp.medium.com/the-hand-y-etiquet…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"D0ZNPP:0C2FCF0287AEFF54B886B3013D571884"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-04T08:13:23"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-05-14T06:55:29"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-05-14T06:55:29"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Ivan Novikov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-14T03:55:29Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Hand-y Etiquette of Modern All-Remote Cu…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"d0znpp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/d0znpp/D0ZNPP:0C2FCF0287…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `25` |

