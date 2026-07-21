# `zdt`  ·  ~39k documents

ZDT collection from the NVD includes vendor-specific advisories and CVEs focusing on zero-day vulnerabilities across various products.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-1639"]` |
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An attacker who can pass input to the asteva…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.9, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-1639", "date": "2026-07-09…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://0day.today/exploit/description/39943"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"1337DAY-ID-39943"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-03-22T05:18:21"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-03-13T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-03-13T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nxploited"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"import argparse\nimport requests\nfrom bs4 i…` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://0day.today/exploit/39943"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}, object{created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-14T00:58:58Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"WordPress Elementor Pro Animation Addon 1.6 …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdt"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/zdt/1337DAY-ID-39943"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `424` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `verified` | `bool` | Whether the exploit/finding was verified. | `true` |

### Collection fields

Specific to the `zdt` collection.

| field | type | description | example |
|---|---|---|---|
| `category` | `str` | Category assigned by the source. | `"web applications"` |

