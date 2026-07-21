# `mskb`  ·  ~12k documents

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-49183", "CVE-2026-49796", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"None\nNone\n"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49183", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.microsoft.com/en-us/help/512…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KB5121767"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T00:18:38"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T00:18:39.242000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"July 18, 2026\u2014KB5121767 (OS Builds 2620…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mskb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mskb/KB5121767"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `41` |

### Family fields

Added by the [`MicrosoftBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `kb` | `str` | Microsoft Knowledge Base article id. | `"KB5121767"` |
| `msplatform` | `str` | Affected Microsoft platform. | `"Windows 10 Version 22H2 for 32-bit Systems"` |
| `msseverity` | `str` | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[str]` | Updates that supersede this update. | `["KB5101649"]` |
| `superseeds` | `list[str]` | Updates this update supersedes. | `["KB5043178", "KB5065426", "KB5059087", "KB50…` |

### Collection fields

Specific to the `mskb` collection.

| field | type | description | example |
|---|---|---|---|
| `affectedProducts` | `list[str]` | Affected product names. | `["Windows 10 Version 22H2 for 32-bit Systems"…` |
| `mscve` | `str` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-58598"` |
| `msfamily` | `str` | Microsoft product family. | `"ESU"` |
| `msimpact` | `str` | Microsoft's impact classification. | `"Elevation of Privilege"` |
| `msproducts` | `list[str]` | Affected Microsoft products. | `["11930", "12098", "11931", "12099", "12097",…` |

