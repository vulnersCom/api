# `wallarmlab`  ·  ~550 documents

Wallarm Lab provides security advisories and CVEs focused on web application vulnerabilities across various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"_Editor's note: This article was originally …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lab.wallarm.com/clearing-up-the-term…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WALLARMLAB:F205C6FCD2CFCEAC7B97D09EA6187C01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T21:36:51"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-13T21:18:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-13T21:18:13"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Tim Erlin"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-13T21:36:51.376000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"AI Control Platform vs. AI Firewall vs. AI G…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wallarmlab"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wallarmlab/WALLARMLAB:F2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

