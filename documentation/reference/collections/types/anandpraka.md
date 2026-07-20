# `anandpraka`  ·  ~6 documents

AnandPraka provides security advisories and CVEs focused on vulnerabilities in various software products and operating systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Summary:\n\nThis blog post is about an I…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.anandpraka.sh/2017/05/how-i-took-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANANDPRAKA:E923C02933F806CD63FC04F38A23CAA2"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-07-29T13:18:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-05-28T14:38:32"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-05-28T14:38:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Anand Prakash (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-05-28T11:38:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"How I took control of your Twitter account (…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"anandpraka"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/anandpraka/ANANDPRAKA:E9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `161` |

