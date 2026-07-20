# `nvd`  ·  ~370k documents

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cwe` | `list[str]` | 25% | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{dependencies,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-2445 enables …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVD:CVE-2026-2445"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:24:47"` |
| `metrics` | `object{cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:16:30"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T08:16:30"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"nvd@nist.gov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `source_references` | `list[object{source,url}]` | 100% | References with their originating source. | `[{"url": "https://security.docs.wso2.com/en/l…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:24:47.540000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nvd/NVD:CVE-2026-2445"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |
| `vulnStatus` | `str` | 100% | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

