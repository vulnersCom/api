# `joomla`  ·  ~750 documents

Joomla collection includes security advisories, CVEs, and patches specific to vulnerabilities in the Joomla CMS platform.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JVEL:876"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:36:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T22:37:12"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T22:37:12"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:36:53.763000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"chronoforms"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"joomla"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/joomla/JVEL:876"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"velteam"` |

### Collection fields

Specific to the `joomla` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "5.4.7", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48957"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@joomla.org", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A new update is now available:\n\nhttps://ww…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48957", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://vel.joomla.org"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.chronoengine.com/downloads/chro…` |

