# `veracode`  ·  ~38k documents

Veracode provides security advisories and vulnerability data focused on application security for various software products and vendors.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "0.3.0", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-55513"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 30% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"github.com/forgekeep/nebula-mesh is vulnerab…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://sca.analysiscenter.veracode.com/vuln…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VERACODE:186139"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T14:18:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 35% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T10:40:31"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T13:45:40"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/forgekeep/nebula-mesh/co…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Veracode Vulnerability Database"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T03:31:47.346000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Improper Enforcement Of Security Policy"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"veracode"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/veracode/VERACODE:186139"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

