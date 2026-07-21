# `cve`  ·  ~370k documents

The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE-2026-2445"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:30:15"` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:16:30"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"WSO2"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:24:02.757000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cve/CVE-2026-2445"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`CveBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `aiDescription` | `str` | AI-generated summary of the vulnerability. | `"**CVE-2026-2445** involves a reflected cross…` |
| `cnaAffected` | `list[object{collectionURL,cpes,defaultStatus,packageName,product,vendor}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,repo,vendor,versions}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"vendor": "WSO2", "product": "WSO2 API Mana…` |
| `cpeConfigurations` | `object{_index,cnaCpeConfiguration}, object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"cnaCpeConfiguration": [{"operator": "OR", "…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `solutions` | `list[object{lang,supportingMedia,value}]` | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "Follow the instruct…` |
| `vulnStatus` | `str` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |
| `webApplicability` | `object{applicable,vulnerabilities}` | Web-application applicability assessment. | `{"applicable": null, "vulnerabilities": []}` |
| `workarounds` | `list[object{lang,value}]` | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Until an update tha…` |

### Collection fields

Specific to the `cve` collection.

| field | type | description | example |
|---|---|---|---|
| `assigned` | `str` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-02-13T07:48:55"` |
| `cnaCpeApplicability` | `list[object{nodes,operator}]` | CPE applicability as supplied by the CNA. | `[{"operator": "OR", "nodes": [{"operator": "O…` |
| `extraReferences` | `list[object{url}]` | Additional reference URLs beyond the primary set. | `[{"url": "https://security.docs.wso2.com/en/l…` |
| `impacts` | `list[object{capecId,descriptions}]` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-22", "descriptions": [{"l…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"composite"` |

