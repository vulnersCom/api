# `rapid7blog`  ·  ~1.7k documents

Rapid7 Blog provides insights on security vulnerabilities, advisories, and exploit techniques relevant to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 70% | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 60% | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `cvss4` | `object{cvssV4}` | 25% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Overview\n\nOn July 17, 2026, a GitHub Se…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 65% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.rapid7.com/blog/post/etr-cve-202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7BLOG:20F3692F768CBC3939DA6DEE73C29ECC"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:38:32"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 70% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T22:23:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T22:23:03"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Rapid7 Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:36:54.236000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-63030: wp2shell a Critical Remote C…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7blog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rapid7blog/RAPID7BLOG:20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

