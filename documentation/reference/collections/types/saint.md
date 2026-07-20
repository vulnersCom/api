# `saint`  ·  ~4.3k documents

SAINT provides vulnerability advisories and CVEs focused on various software products and operating systems, sourced from multiple security vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 55% | Related CVE identifiers referenced by this document. | `["CVE-2026-8037"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 55% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Added: 07/02/2026  \nCVE: CVE-2026-8037  \n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 50% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-8037", "date": "2026-07-15…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://download.saintcorporation.com/cgi-bi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAINT:B94055400BC099146F61734DD1B7933A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T20:16:52"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 55% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SAINT Corporation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T07:56:39.754000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Progress LoadMaster API command injection"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"saint"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/saint/SAINT:B94055400BC0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

