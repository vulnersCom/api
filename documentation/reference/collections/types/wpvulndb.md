# `wpvulndb`  ·  ~15k documents

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-12256"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Description The Avada theme for WordPress is…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10024", "date": "2026-06-2…` |
| `exploit` | `str` | 100% | Exploit availability/details (source-specific). | `"https://example.com/wp-content/plugins/8-deg…` |
| `generation` | `int` | 100% | Internal generation/version counter of the record. | `0` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://wpscan.com/vulnerability/5cc071ff-6e…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPVDB-ID:5CC071FF-6EE6-4396-B8F2-A2A610855C03"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T20:25:15"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://www.wordfence.com/threat-intel/vuln…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"wpvulndb"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-10T20:25:15.222000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Avada < 3.15.4 - Authenticated (Contributor+…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpvulndb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wpvulndb/WPVDB-ID:5CC071…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

