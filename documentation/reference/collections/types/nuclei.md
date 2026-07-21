# `nuclei`  ·  ~4.2k documents

Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NUCLEI:CVE-2026-8732"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T23:48:06"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:11:04"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T12:22:44"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T11:44:26.385000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"WP Maps Pro (wp-google-map-gold) <= 6.1.0 - …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nuclei"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nuclei/NUCLEI:CVE-2026-8…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `scanner`-family document (typed by [`ScannerBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The WP Maps Pro plugin for WordPress is vuln…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/projectdiscovery/nuclei-t…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ProjectDiscovery"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"id: CVE-2026-8732\n\ninfo:\n  name: WP Maps …` |

### Collection fields

Specific to the `nuclei` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-8732"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@wordfence.co…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-32778", "date": "2026-07-1…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@wordf…` |
| `references` | `list[str]` | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-8…` |

