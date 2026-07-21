# `veracode`  ·  ~38k documents

Veracode provides security advisories and vulnerability data focused on application security for various software products and vendors.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-55513"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"github.com/forgekeep/nebula-mesh is vulnerab…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://sca.analysiscenter.veracode.com/vuln…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VERACODE:186139"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T14:18:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T10:40:31"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T13:45:40"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/forgekeep/nebula-mesh/co…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Veracode Vulnerability Database"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T03:31:47.346000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Improper Enforcement Of Security Policy"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"veracode"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/veracode/VERACODE:186139"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "0.3.0", "operator": "le", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `veracode` collection.

_None in the sample._

