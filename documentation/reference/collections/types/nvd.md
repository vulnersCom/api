# `nvd`  ·  ~370k documents

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVD:CVE-2026-15156"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:24:09"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T05:16:34"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T05:16:34"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:24:09.464000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-15156"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nvd/NVD:CVE-2026-15156"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Present in every sampled `cve`-family document (typed by [`CveBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15156"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The Essential Addons for Elementor \u2013 Po…` |
| `enchantments` | `object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Stored XSS in Essentia…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"security@wordfence.com"` |

### Collection fields

Specific to the `nvd` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.4, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@wordfence.co…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@hcl.com", "versi…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-79"]` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@wordf…` |
| `origin` | `str` | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `references` | `list[str]` | External reference URLs. | `["https://plugins.trac.wordpress.org/browser/…` |
| `source_references` | `list[object{source,url}]` | References with their originating source. | `[{"url": "https://plugins.trac.wordpress.org/…` |
| `vulnStatus` | `str` | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

