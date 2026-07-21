# `cvelist`  ·  ~370k documents

CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "wso2", "version": "3.…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-2445: Reflect…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cve.org/CVERecord?id=CVE-2026-2445"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVELIST:CVE-2026-2445"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:19:22"` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "wso2", "versio…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:06:39"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"WSO2"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:19:22.197000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-2445 Reflected Cross-Site Scripting…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cvelist"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cvelist/CVELIST:CVE-2026…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`CveBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cnaAffected` | `list[object{collectionURL,cpes,defaultStatus,packageName,product,vendor}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,repo,vendor,versions}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"vendor": "WSO2", "product": "WSO2 API Mana…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `solutions` | `list[object{lang,supportingMedia,value}]` | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "Follow the instruct…` |
| `workarounds` | `list[object{lang,value}]` | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Until an update tha…` |

### Collection fields

Specific to the `cvelist` collection.

| field | type | description | example |
|---|---|---|---|
| `assigned` | `str` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-02-13T07:48:55"` |
| `cnaCpeApplicability` | `list[object{nodes,operator}]` | CPE applicability as supplied by the CNA. | `[{"operator": "OR", "nodes": [{"operator": "O…` |
| `dateUpdated` | `str` | Source-reported last-update date. | `"2026-07-20T08:06:39"` |
| `impacts` | `list[object{capecId,descriptions}]` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-22", "descriptions": [{"l…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"cve.mitre.org"` |
| `provider` | `str` | Organization that produced the record (e.g. the CNA). | `"WSO2"` |

