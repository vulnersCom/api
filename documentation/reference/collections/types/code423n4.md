# `code423n4`  ·  ~10k documents

Code423n4 is a vulnerability database focused on security advisories and reports for smart contracts and blockchain projects.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: crypto`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"crypto"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[Lines of code](https://github.com/code-423n…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/code-423n4/2024-01-canto-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CODE423N4:2024-01-CANTO-FINDINGS-ISSUES-12"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-07T20:21:07"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-02-05T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-01-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Code4rena"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-01-27T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"secRewardsPerShare Insufficient precision"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"code423n4"` |
| `vendor_severity` | `str` | 100% | Vendor's own qualitative severity rating. | `"2 (Med Risk)"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/code423n4/CODE423N4:2024…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `30` |

