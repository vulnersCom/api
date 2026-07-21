# `nvd`  ·  ~370k documents

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

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
| `enchantments` | `object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-2445 enables …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVD:CVE-2026-2445"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:24:47"` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:16:30"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:16:30"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"nvd@nist.gov"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:24:47.540000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nvd/NVD:CVE-2026-2445"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`CveBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `vulnStatus` | `str` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

### Collection fields

Specific to the `nvd` collection.

| field | type | description | example |
|---|---|---|---|
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `source_references` | `list[object{source,url}]` | References with their originating source. | `[{"url": "https://security.docs.wso2.com/en/l…` |

