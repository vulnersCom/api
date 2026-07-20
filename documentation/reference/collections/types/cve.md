# `cve`  ·  ~370k documents

The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `aiDescription` | `str` | 100% | AI-generated summary of the vulnerability. | `"**CVE-2026-2445** involves a reflected cross…` |
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-02-13T07:48:55"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cnaAffected` | `list[object{collectionURL,cpes,defaultStatus,packageName,product,vendor}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,repo,vendor,versions}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"vendor": "WSO2", "product": "WSO2 API Mana…` |
| `cnaCpeApplicability` | `list[object{nodes,operator}]` | 5% | CPE applicability as supplied by the CNA. | `[{"operator": "OR", "nodes": [{"operator": "O…` |
| `cpeConfigurations` | `object{_index,cnaCpeConfiguration}, object{_index,vulnersCpeConfiguration}` | 80% | CPE applicability configurations (NVD-style match tree). | `{"cnaCpeConfiguration": [{"operator": "OR", "…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cwe` | `list[str]` | 25% | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `extraReferences` | `list[object{url}]` | 100% | Additional reference URLs beyond the primary set. | `[{"url": "https://security.docs.wso2.com/en/l…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE-2026-2445"` |
| `impacts` | `list[object{capecId,descriptions}]` | 10% | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-22", "descriptions": [{"l…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:30:15"` |
| `metrics` | `object{cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:16:30"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"composite"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"WSO2"` |
| `solutions` | `list[object{lang,supportingMedia,value}]` | 5% | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "Follow the instruct…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:24:02.757000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cve/CVE-2026-2445"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |
| `vulnStatus` | `str` | 100% | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |
| `webApplicability` | `object{applicable,vulnerabilities}` | 100% | Web-application applicability assessment. | `{"applicable": null, "vulnerabilities": []}` |
| `workarounds` | `list[object{lang,value}]` | 20% | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Until an update tha…` |

