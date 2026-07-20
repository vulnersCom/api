# `patchstack`  ·  ~47k documents

Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.40.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `classification` | `str` | 100% | Source-specific classification/category of the issue. | `"Other Vulnerability Type"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53496"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://patchstack.com/database/npm/plugin/e…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PATCHSTACK:CBE40482C25309E8731F3439AF8CFEB4"` |
| `isExploited` | `bool` | 100% | Whether the vulnerability is known to be exploited. | `false` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T20:37:03"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T20:19:39"` |
| `owasp` | `str` | 100% | Related OWASP category. | `"A1: Broken Access Control"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T20:19:39"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/mattiasw/ExifReader/secu…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Patchstack"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T20:37:15.463000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"patchstack"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/patchstack/PATCHSTACK:CB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

