# `paloalto`  ·  ~510 documents

Palo Alto Networks collection includes advisories and CVEs related to their security products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-0119"]` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | 15% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `cvss4` | `object{cvssV4}` | 100% | CVSS v4.0 score block. | `{"cvssV4": {"version": "4.0", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A command injection vulnerability\u00a0in th…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.0, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-0119", "date": "2026-07-14…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://securityadvisories.paloaltonetworks.…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PA-CVE-2025-0119"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T14:48:48"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-04-09T16:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-04-09T16:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.paloaltonetworks.com/CVE-2…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Palo Alto Networks Product Security Incident…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-09T16:36:16Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Cortex XDR Broker VM: Authenticated Command …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"paloalto"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/paloalto/PA-CVE-2025-0119"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `28` |

