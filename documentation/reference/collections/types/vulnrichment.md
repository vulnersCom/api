# `vulnrichment`  ·  ~160k documents

Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-07-08T16:10:36"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15093"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-601"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"IBM Engineering AI Hub 1.0.0, 1.1.0, and 1.2…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.9, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15093", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/cisagov/vulnrichment/blob…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNRICHMENT:CVE-2026-15093"` |
| `impacts` | `list[?], list[object{capecId,descriptions}]` | 100% | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-66", "descriptions": [{"l…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T00:23:49"` |
| `metrics` | `object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "ibm", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T19:37:57"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"cisa.gov"` |
| `provider` | `str` | 100% | Organization that produced the record (e.g. the CNA). | `"ibm"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T19:37:57"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.ibm.com/support/pages/node/7279…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ibm"` |
| `solutions` | `list[?], list[object{lang,supportingMedia,value}]` | 100% | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "IBM strongly recomm…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T00:23:49.406000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-15093 Multiple Vulnerabilities in I…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnrichment"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnrichment/VULNRICHMEN…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

