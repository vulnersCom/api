# `cvelist`  ·  ~370k documents

CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-02-13T07:48:55"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cnaAffected` | `list[object{collectionURL,cpes,defaultStatus,packageName,product,vendor}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,repo,vendor,versions}], list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"vendor": "WSO2", "product": "WSO2 API Mana…` |
| `cnaCpeApplicability` | `list[object{nodes,operator}]` | 5% | CPE applicability as supplied by the CNA. | `[{"operator": "OR", "nodes": [{"operator": "O…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "wso2", "version": "3.…` |
| `cwe` | `list[str]` | 25% | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `dateUpdated` | `str` | 100% | Source-reported last-update date. | `"2026-07-20T08:06:39"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{dependencies,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-2445: Reflect…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cve.org/CVERecord?id=CVE-2026-2445"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVELIST:CVE-2026-2445"` |
| `impacts` | `list[object{capecId,descriptions}]` | 10% | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-22", "descriptions": [{"l…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:19:22"` |
| `metrics` | `object{cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "wso2", "versio…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:06:39"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"cve.mitre.org"` |
| `provider` | `str` | 100% | Organization that produced the record (e.g. the CNA). | `"WSO2"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"WSO2"` |
| `solutions` | `list[object{lang,supportingMedia,value}]` | 5% | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "Follow the instruct…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:19:22.197000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-2445 Reflected Cross-Site Scripting…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cvelist"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cvelist/CVELIST:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |
| `workarounds` | `list[object{lang,value}]` | 20% | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Until an update tha…` |

