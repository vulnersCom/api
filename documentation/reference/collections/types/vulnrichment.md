# `vulnrichment`  ·  ~160k documents

Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15093"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "ibm", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "amzn", "version": "4.0…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"IBM Engineering AI Hub 1.0.0, 1.1.0, and 1.2…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.9, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15093", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/cisagov/vulnrichment/blob…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNRICHMENT:CVE-2026-15093"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T00:23:49"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "ibm", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T19:37:57"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T19:37:57"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.ibm.com/support/pages/node/7279…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ibm"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T00:23:49.406000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-15093 Multiple Vulnerabilities in I…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnrichment"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vulnrichment/VULNRICHMEN…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Added by the [`CveBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-601"]` |
| `solutions` | `list[object{lang,supportingMedia,value}]` | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "IBM strongly recomm…` |

### Collection fields

Specific to the `vulnrichment` collection.

| field | type | description | example |
|---|---|---|---|
| `assigned` | `str` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-07-08T16:10:36"` |
| `impacts` | `list[object{capecId,descriptions}]` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-66", "descriptions": [{"l…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"cisa.gov"` |
| `provider` | `str` | Organization that produced the record (e.g. the CNA). | `"ibm"` |

