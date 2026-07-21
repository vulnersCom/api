# `impervablog`  ·  ~1k documents

Imperva Blog provides insights and advisories on web application security, focusing on vulnerabilities and exploits related to Imperva products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@puppet.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"_**TL;DR :****** A critical pre-authenticati…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.imperva.com/blog/imperva-custome…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"IMPERVABLOG:9228B71EDF0F5FABCFC52890D7714F10"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T17:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T17:02:40"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T17:02:40"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Bar Menachem"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T17:36:53.454000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Imperva Customers Protected Against \u201cwp…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"impervablog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/impervablog/IMPERVABLOG:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `impervablog` collection.

_None in the sample._

