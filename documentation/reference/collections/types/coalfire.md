# `coalfire`  ·  ~600 documents

Coalfire provides security advisories and vulnerability reports focused on various vendors and products, primarily for compliance and risk management.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Organizations that want to pursue ISO 42001 …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.8, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.coalfire.com/the-coalfire-blog/p…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"COALFIRE:A3A400ED82636541769021632F5593B0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-06T21:53:03"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-02-06T16:23:35"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-02-06T16:23:35"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"The Coalfire Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-02-06T13:23:35Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Privacy information management system consid…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coalfire"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/coalfire/COALFIRE:A3A400…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

