# `jvn`  ·  ~5.6k documents

The JVN collection provides advisories and CVEs related to vulnerabilities in various software products and operating systems sourced from Japan's security community.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: jvn`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"jvn"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-54518", "CVE-2026-21530", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Overview\n\nCVE-2025-54518 \| AMD: CVE-2025…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 0.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44024", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jvndb.jvn.jp/en/contents/2026/JVNDB-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JVNDB-2026-024104"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T01:37:02"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T03:28:23"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T03:28:23"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.hitachi.com/products/it/storage…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Japan Vulnerability Notes"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T01:37:02.979000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security information for Hitachi Disk Array …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jvn"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jvn/JVNDB-2026-024104"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

