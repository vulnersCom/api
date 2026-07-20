# `packetstormnews`  ·  ~6.9k documents

Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 10% | Related CVE identifiers referenced by this document. | `["CVE-2026-14440"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "cna", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@cloudflare.com", "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"GNUnet is a peer-to-peer framework with focu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/213585/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORMNEWS:213585"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-08T07:35:00"` |
| `metrics` | `object{adp,cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cna", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-12-29T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-12-29T00:00:00"` |
| `reporter` | `str` | 90% | Person or organization credited with reporting/authoring it. | `"Christian Grothoff"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/213585"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T07:35:00.709000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"GNUnet P2P Framework 0.26.2"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstormnews"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/packetstormnews/PACKETST…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `369` |

