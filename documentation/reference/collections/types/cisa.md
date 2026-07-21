# `cisa`  ·  ~4.2k documents

CISA collection includes advisories and alerts from the Cybersecurity and Infrastructure Security Agency, focusing on vulnerabilities across various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48907"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@joomla.org", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"CISA has added one new vulnerability to its …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48907", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cisa.gov/news-events/alerts/2026…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISA:DD804083B370CD5692E9EFFB700BBA8F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-18T05:43:51"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-16T12:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-16T12:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["/known-exploited-vulnerabilities-catalog", …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CISA"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-17T05:43:59.841000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"\nCISA Adds One Known Exploited Vulnerabilit…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisa"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cisa/CISA:DD804083B370CD…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `true` |

### Collection fields

Specific to the `cisa` collection.

_None in the sample._

