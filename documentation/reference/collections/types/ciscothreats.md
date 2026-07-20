# `ciscothreats`  ·  ~14k documents

Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `ciscoThreat` | `object{files,md5,messageBody,size,subject}` | 100% | Cisco Talos threat details (files, hashes, subject). | `{"md5": "c130666367eb5724a23d046a7963df5e", "…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Medium\n\nAlert ID: \n\n58703\n\nFirst Publi…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/view…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-THREAT-58703"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-15T17:08:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2018-08-15T15:55:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2018-08-15T15:55:56"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-08-15T12:55:56Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Threat Outbreak Alert RuleID33317: Email Mes…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ciscothreats"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ciscothreats/CISCO-THREA…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `542` |

