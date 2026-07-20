# `sqlite`  ·  ~48 documents

SQLite vulnerabilities collection includes advisories and CVEs related to SQLite database software, focusing on security issues affecting its functionality.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 65% | Affected software products (name/version/operator). | `[{"version": "3.53.2", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11822"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 15% | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An attacker who can execute arbitrary SQL (f…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-6965", "date": "2026-06-28…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SQLT:CVE-2026-11822"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-25T03:15:15"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-01-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SQLite ORG"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-25T03:15:15.740000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SQLite report about CVE-2026-11822"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sqlite"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sqlite/SQLT:CVE-2026-11822"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

