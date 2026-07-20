# `contao`  ·  ~29 documents

Contao vulnerability collection provides advisories and CVEs specific to the Contao CMS, sourced from security bulletins and community reports.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.0", "operator": "eq", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-45398"]` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | 100% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Date** : 2024-09-17  \n**CVE ID** : CVE-20…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.8, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-45398", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://contao.org/en/security-advisories/re…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CONTAO:REMOTE-COMMAND-EXECUTION-THROUGH-FILE…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-16T15:11:19"` |
| `metrics` | `object{adp,cna,nvd}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-09-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-09-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Contao org"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-09-16T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Remote command execution through file uploads"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"contao"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/contao/CONTAO:REMOTE-COM…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `75` |

