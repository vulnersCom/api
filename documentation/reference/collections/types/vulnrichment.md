# `vulnrichment`  ·  ~160k documents

Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNRICHMENT:CVE-2026-55550"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T22:21:43"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T21:02:16"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T21:02:16"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T22:21:43.342000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-55550 NextCRM has RBAC Bypass in MC…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnrichment"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vulnrichment/VULNRICHMEN…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `cve`-family document (typed by [`CveBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-55550"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"NextCRM is open-source customer relationship…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"GitHub_M"` |

### Collection fields

Specific to the `vulnrichment` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `assigned` | `str` | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-06-16T23:01:04"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "github_m", "version":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "github_m", "version": …` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-269", "CWE-284", "CWE-862"]` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/cisagov/vulnrichment/blob…` |
| `impacts` | `list[object{capecId,descriptions}]` | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-18", "descriptions": [{"l…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "github_m", "ve…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"cisa.gov"` |
| `provider` | `str` | Organization that produced the record (e.g. the CNA). | `"GitHub_M"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/pdovhomilja/nextcrm-app/…` |

