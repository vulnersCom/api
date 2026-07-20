# `ncsc`  ·  ~4.2k documents

The NCSC collection includes UK government advisories and alerts on cybersecurity vulnerabilities across various vendors and products, featuring CVEs and mitigation guidance.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: ncsc`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"ncsc"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"There are two vulnerabilities present in Wor…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.4, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://advisories.ncsc.nl/2026/ncsc-2026-02…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NCSC-2026-0250"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:38:05"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T11:01:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T11:01:56"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://slcyber.io/research-center/wp2shell…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"NCSC"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:38:05.958000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WordPress vulnerabilities can be addressed t…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ncsc"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ncsc/NCSC-2026-0250"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

