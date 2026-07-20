# `amd`  ·  ~190 documents

AMD's vulnerability collection includes advisories and CVEs related to AMD hardware and software products, focusing on security issues affecting their technology.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-40677"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.7, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 10% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 30% | CVSS v3.x score block. | `{"cvssV31": {"source": "arm-security", "versi…` |
| `cvss4` | `object{cvssV4}` | 75% | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@amd.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## CVE Details\n\nRefer to Glossary for expl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-40677", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.amd.com/en/resources/product-sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AMD-SB-9027"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-12T18:52:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | 90% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt@amd.com",…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-09T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"amd.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T00:55:26.325000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"AMD Auto Updater Vulnerability"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/amd/AMD-SB-9027"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

