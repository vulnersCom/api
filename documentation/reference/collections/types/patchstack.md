# `patchstack`  ·  ~47k documents

Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PATCHSTACK:18E0566C19094BEEAA9A3F164E2D36C2"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T23:43:58"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T23:26:27"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T23:26:27"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T23:44:03.309000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"NPM: Astro: composable astro/hono pipeline…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"patchstack"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/patchstack/PATCHSTACK:18…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Patchstack"` |

### Collection fields

Specific to the `patchstack` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "7.0.0", "operator": "ge", "name…` |
| `classification` | `str` | Source-specific classification/category of the issue. | `"Cross Site Request Forgery (CSRF)"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-12590"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"NPM: Astro: composable astro/hono pipeline…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://patchstack.com/database/npm/plugin/a…` |
| `isExploited` | `bool` | Whether the vulnerability is known to be exploited. | `false` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/withastro/astro/security…` |

