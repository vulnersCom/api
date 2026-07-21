# `nuclei`  ·  ~4.1k documents

Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-29059"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Windmill < 1.603.3 contains a path traversal…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-29059", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/projectdiscovery/nuclei-t…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NUCLEI:CVE-2026-29059"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T12:00:07"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-03T04:09:58"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-19T04:10:42"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/Chocapikk/Windfall", "ht…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ProjectDiscovery"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"id: CVE-2026-29059\n\ninfo:\n  name: Windmil…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-03T09:32:48.500000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Windmill/Nextcloud Flow < 1.603.3 - Unauthen…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nuclei"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nuclei/NUCLEI:CVE-2026-2…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Added by the [`ScannerBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `nuclei` collection.

_None in the sample._

