# `nginx`  ·  ~62 documents

Nginx vulnerability collection includes advisories and CVEs related to the Nginx web server, focusing on security issues affecting its software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60005"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Memory disclosure when using ngx_http_slice_…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60005", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://cve.mitre.org/cgi-bin/cvename.cgi?nam…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NGINX:CVE-2026-60005"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T15:04:21"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T15:04:21"` |
| `references` | `list[str]` | External reference URLs. | `["https://my.f5.com/manage/s/article/K0001621…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nginx"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:36:52.141000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Memory disclosure when using ngx_http_slice_…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nginx"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nginx/NGINX:CVE-2026-60005"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `19` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.31.2", "operator": "le", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `nginx` collection.

_None in the sample._

