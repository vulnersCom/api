# `mskb`  ·  ~12k documents

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedProducts` | `list[?], list[str]` | 100% | Affected product names. | `["Windows 10 Version 22H2 for 32-bit Systems"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49183", "CVE-2026-49796", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"None\nNone\n"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49183", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.microsoft.com/en-us/help/512…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KB5121767"` |
| `kb` | `str` | 100% | Microsoft Knowledge Base article id. | `"KB5121767"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T00:18:38"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:00:00"` |
| `mscve` | `str` | 100% | Microsoft's CVE identifier for the advisory. | `"CVE-2026-58598"` |
| `msfamily` | `str` | 100% | Microsoft product family. | `"ESU"` |
| `msimpact` | `str` | 100% | Microsoft's impact classification. | `"Elevation of Privilege"` |
| `msplatform` | `str` | 100% | Affected Microsoft platform. | `"Windows 10 Version 22H2 for 32-bit Systems"` |
| `msproducts` | `list[?], list[str]` | 100% | Affected Microsoft products. | `["11930", "12098", "11931", "12099", "12097",…` |
| `msseverity` | `str` | 100% | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[?], list[str]` | 100% | Updates that supersede this update. | `["KB5101649"]` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `superseeds` | `list[?], list[str]` | 100% | Updates this update supersedes. | `["KB5043178", "KB5065426", "KB5059087", "KB50…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T00:18:39.242000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"July 18, 2026\u2014KB5121767 (OS Builds 2620…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mskb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mskb/KB5121767"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `40` |

