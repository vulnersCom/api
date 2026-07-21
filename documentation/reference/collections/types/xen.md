# `xen`  ·  ~480 documents

Xen collection includes security advisories and CVEs related to the Xen hypervisor, covering vulnerabilities affecting virtualization environments.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42491"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@amd.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"#### ISSUE DESCRIPTION\nXAPI provides SDKs; …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42488", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://xenbits.xen.org/xsa/advisory-498.html"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"XSA-498"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T13:37:21"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T12:05:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T12:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Xen Project"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T13:37:21.925000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"XAPI: Missing TLS verification in some SDKs"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"xen"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/xen/XSA-498"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "4.15", "operator": "ge", "name"…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `xen` collection.

_None in the sample._

