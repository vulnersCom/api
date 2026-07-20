# `huntr`  ·  ~4.1k documents

Huntr is a vulnerability database that aggregates security advisories, CVEs, and exploits primarily focused on open-source software projects.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvelist` | `list[str]` | 85% | Related CVE identifiers referenced by this document. | `["CVE-2026-12484"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 85% | CVSS v3.x score block. | `{"cvssV3": {"source": "security@huntr.dev", "…` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve-coordination@googl…` |
| `cwe_id` | `str` | 95% | Single associated CWE identifier. | `"d32d"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This report is not public"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.4, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 75% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-12228", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.huntr.dev/bounties/ab14df49-13b5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AB14DF49-13B5-4442-B754-3189430BFA28"` |
| `language` | `str` | 100% | Language of the report. | `"Python"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T21:36:58"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 85% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"source": "security@huntr.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-17T02:52:34"` |
| `patch_commit_sha` | `str` | 55% | Commit SHA of the fixing patch. | `"f9b1eb510478570609ef451984a255775aa4b937"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-20T19:47:09"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"jinyimeng01"` |
| `repository` | `str` | 55% | Source code repository associated with the report. | `"https://github.com/mlflow/mlflow"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `status` | `str` | 100% | Workflow status of the record. | `"valid"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T21:36:58.151000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unsafe Deserialization in Public keras.laye…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huntr"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/huntr/AB14DF49-13B5-4442…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

