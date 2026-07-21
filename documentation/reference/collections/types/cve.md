# `cve`  ·  ~370k documents

The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE-2026-13439"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:41:15"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T05:35:29"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T05:35:29"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:41:15.376000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-13439 Easy Form Builder by WhiteStu…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cve/CVE-2026-13439"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `cve`-family document (typed by [`CveBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-13439"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The Easy Form Builder by WhiteStudio plugin …` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Wordfence"` |

### Collection fields

Specific to the `cve` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `aiDescription` | `str` | AI-generated summary of the vulnerability. | `"Technical details (affected products, versio…` |
| `assigned` | `str` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-06-26T15:53:18"` |
| `cnaAffected` | `list[object{collectionURL,cpes,defaultStatus,packageName,product,vendor}], list[object{cpes,modules,product,vendor,versions}], list[object{cpes,product,vendor,versions}], list[object{defaultStatus,product,vendor,versions}], list[object{product,vendor,versions}]` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"vendor": "hassantafreshi", "product": "Eas…` |
| `cnaCpeApplicability` | `list[object{nodes,operator}]` | CPE applicability as supplied by the CNA. | `[{"operator": "OR", "nodes": [{"operator": "O…` |
| `cpeConfigurations` | `object{_index,cnaCpeConfiguration}, object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "wordfence", "version"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "hcl", "version": "4.0"…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-269"]` |
| `extraReferences` | `list[object{url}]` | Additional reference URLs beyond the primary set. | `[{"url": "https://plugins.trac.wordpress.org/…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cve.org/CVERecord?id=CVE-2026-13…` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "wordfence", "v…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"composite"` |
| `references` | `list[str]` | External reference URLs. | `["https://plugins.trac.wordpress.org/browser/…` |
| `vulnStatus` | `str` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |
| `webApplicability` | `object{applicable,vulnerabilities}` | Web-application applicability assessment. | `{"applicable": null, "vulnerabilities": []}` |
| `workarounds` | `list[object{lang,value}]` | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Restrict network eg…` |

