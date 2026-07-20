# `impervablog`  ·  ~1k documents

Imperva Blog provides insights and advisories on web application security, focusing on vulnerabilities and exploits related to Imperva products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 45% | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 40% | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@puppet.com", …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"_**TL;DR :****** A critical pre-authenticati…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.imperva.com/blog/imperva-custome…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"IMPERVABLOG:9228B71EDF0F5FABCFC52890D7714F10"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T17:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 45% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T17:02:40"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T17:02:40"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Bar Menachem"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T17:36:53.454000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Imperva Customers Protected Against \u201cwp…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"impervablog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/impervablog/IMPERVABLOG:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

