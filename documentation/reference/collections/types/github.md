# `github`  ·  ~33k documents

GitHub collection includes vulnerability advisories and CVEs related to open-source projects hosted on GitHub, focusing on various software products and libraries.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GHSA-H95V-H523-3MW8"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T23:53:49"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T23:28:38"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T23:28:36"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T23:53:49.812000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Guzzle: URI fragments disclosed in redirect …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"github"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/github/GHSA-H95V-H523-3MW8"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"GitHub Advisory Database"` |

### Collection fields

Specific to the `github` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{ecosystem,name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "7.15.1", "operator": "lt", "eco…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-32205"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-201", "CWE-212"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Impact\n\nWhen the optional referer re…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/advisories/GHSA-h95v-h523…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/guzzle/guzzle/security/a…` |

