# `nvd`  ·  ~370k documents

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6656"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-208"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": "CVE-202…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVD:CVE-2026-6656"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:17:17"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:16:42"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:16:42"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://rt.cpan.org/Ticket/Display.html?id=…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"nvd@nist.gov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `source_references` | `list[object{source,url}]` | 100% | References with their originating source. | `[{"url": "https://metacpan.org/release/DRSTEV…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:17:17.832000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-6656"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nvd/NVD:CVE-2026-6656"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |
| `vulnStatus` | `str` | 100% | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

