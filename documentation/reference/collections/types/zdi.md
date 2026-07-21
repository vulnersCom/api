# `zdi`  ·  ~17k documents

The ZDI collection includes advisories and CVEs from the Zero Day Initiative, focusing on vulnerabilities in various software products and vendors.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-27220"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "zdi", "version": "3.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This vulnerability allows remote attackers t…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-27220", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.zerodayinitiative.com/advisories…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ZDI-26-355"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-11T05:58:44"` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "zdi", "versi…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-10T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-10T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://helpx.adobe.com/security/products/a…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Mark Vincent Yason (markyason.github.io)"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-11T05:58:44.411000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Adobe Acrobat Reader DC Annotation Use-After…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdi"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/zdi/ZDI-26-355"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `zdi` collection.

_None in the sample._

