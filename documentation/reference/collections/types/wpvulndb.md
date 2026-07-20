# `wpvulndb`  ·  ~15k documents

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-7544"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 85% | CVSS v3.x score block. | `{"cvssV31": {"source": "security@wordfence.co…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Description The Mux Video Uploader plugin fo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 65% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10024", "date": "2026-06-2…` |
| `exploit` | `str` | 5% | Exploit availability/details (source-specific). | `"https://example.com/wp-content/plugins/8-deg…` |
| `generation` | `int` | 100% | Internal generation/version counter of the record. | `0` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://wpscan.com/vulnerability/8e31419b-83…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPVDB-ID:8E31419B-834D-42ED-B57F-202B1837CEE3"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T20:27:00"` |
| `metrics` | `object{adp,cna}` | 85% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@wordf…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-11T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `references` | `list[str]` | 95% | External reference URLs. | `["https://www.wordfence.com/threat-intel/vuln…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"wpvulndb"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T20:27:00.971000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Mux Video Uploader < 1.1.5 - Authenticated (…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpvulndb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wpvulndb/WPVDB-ID:8E3141…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

