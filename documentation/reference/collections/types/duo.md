# `duo`  ·  ~54 documents

Duo Security's collection features advisories and CVEs related to its authentication products and services, focusing on security vulnerabilities and fixes.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Duo Product Security Advisory\n\n**Advisor…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://duo.com/labs/psa/duo-psa-2014-007"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DUO:D3F6F5E7B4015B33735F13DE1D5791B4"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-01-29T20:54:29"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2014-10-15T04:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2014-10-15T04:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Duo Security Advisories"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2014-10-15T01:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"DUO-PSA-2014-007: Duo Product Security Advis…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"duo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/duo/DUO:D3F6F5E7B4015B33…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `28` |

