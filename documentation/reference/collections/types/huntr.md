# `huntr`  ·  ~4.1k documents

Huntr is a vulnerability database that aggregates security advisories, CVEs, and exploits primarily focused on open-source software projects.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AB14DF49-13B5-4442-B754-3189430BFA28"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T15:37:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-17T02:52:34"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-20T19:47:09"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T21:36:58.151000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Unsafe Deserialization in Public keras.laye…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huntr"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/huntr/AB14DF49-13B5-4442…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `bugbounty`-family document (typed by [`BugBountyBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This report is not public"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.4, "uncertanity": 0.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.huntr.dev/bounties/ab14df49-13b5…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"jinyimeng01"` |

### Collection fields

Specific to the `huntr` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-12484"]` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "security@huntr.dev", "…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve-coordination@googl…` |
| `cwe_id` | `str` | Single associated CWE identifier. | `"d32d"` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-12484", "date": "2026-07-2…` |
| `language` | `str` | Language of the report. | `"Python"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"source": "security@huntr.…` |
| `patch_commit_sha` | `str` | Commit SHA of the fixing patch. | `"f9b1eb510478570609ef451984a255775aa4b937"` |
| `repository` | `str` | Source code repository associated with the report. | `"https://github.com/mlflow/mlflow"` |
| `status` | `str` | Workflow status of the record. | `"valid"` |

