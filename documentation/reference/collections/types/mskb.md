# `mskb`  ·  ~12k documents

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KB5121767"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T00:18:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T00:18:39.242000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"July 18, 2026\u2014KB5121767 (OS Builds 2620…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mskb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mskb/KB5121767"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `43` |

### Family fields

Present in every sampled `microsoft`-family document (typed by [`MicrosoftBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"None\nNone\n"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.microsoft.com/en-us/help/512…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft"` |

### Collection fields

Specific to the `mskb` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedProducts` | `list[str]` | Affected product names. | `["Microsoft SharePoint Enterprise Server 2016"]` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50522", "CVE-2026-54108", "CVE-202…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50522", "date": "2026-07-1…` |
| `kb` | `str` | Microsoft Knowledge Base article id. | `"KB5121767"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `mscve` | `str` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-62826"` |
| `msfamily` | `str` | Microsoft product family. | `"Microsoft Office"` |
| `msimpact` | `str` | Microsoft's impact classification. | `"Spoofing"` |
| `msproducts` | `list[str]` | Affected Microsoft products. | `["10950"]` |
| `msseverity` | `str` | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[str]` | Updates that supersede this update. | `["KB5121767"]` |
| `superseeds` | `list[str]` | Updates this update supersedes. | `["KB5043178", "KB5065426", "KB5059087", "KB50…` |

