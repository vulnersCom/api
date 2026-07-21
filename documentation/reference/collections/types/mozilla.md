# `mozilla`  ·  ~1.6k documents

Mozilla collection includes security advisories and CVEs related to Mozilla products, primarily focusing on vulnerabilities in Firefox and other Mozilla software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15718", "CVE-2026-15719"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.4, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"We are aware that exploit code for this is p…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15718", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.mozilla.org/en-US/security/advis…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MFSA2026-67"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:37:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://bugzilla.mozilla.org/show_bug.cgi?i…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Mozilla Foundation"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:37:54.814000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security Vulnerabilities fixed in Firefox 15…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mozilla"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mozilla/MFSA2026-67"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "152.0.6", "operator": "lt", "na…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `mozilla` collection.

_None in the sample._

