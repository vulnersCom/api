# `zdi`  ·  ~17k documents

The ZDI collection includes advisories and CVEs from the Zero Day Initiative, focusing on vulnerabilities in various software products and vendors.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-27220"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | 100% | CVSS v3.x score block. | `{"cvssV3": {"source": "zdi", "version": "3.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This vulnerability allows remote attackers t…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-27220", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.zerodayinitiative.com/advisories…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ZDI-26-355"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-11T05:58:44"` |
| `metrics` | `object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "zdi", "versi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-10T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://helpx.adobe.com/security/products/a…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Mark Vincent Yason (markyason.github.io)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-11T05:58:44.411000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Adobe Acrobat Reader DC Annotation Use-After…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdi"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/zdi/ZDI-26-355"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

