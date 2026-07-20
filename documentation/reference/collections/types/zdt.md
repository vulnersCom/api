# `zdt`  ·  ~39k documents

ZDT collection from the NVD includes vendor-specific advisories and CVEs focusing on zero-day vulnerabilities across various products.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `category` | `str` | 100% | Category assigned by the source. | `"web applications"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-1639"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An attacker who can pass input to the asteva…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.9, "uncertanity": 0.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-1639", "date": "2026-07-09…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://0day.today/exploit/description/39943"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"1337DAY-ID-39943"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-03-22T05:18:21"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-03-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-03-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nxploited"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"import argparse\nimport requests\nfrom bs4 i…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://0day.today/exploit/39943"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-14T00:58:58Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WordPress Elementor Pro Animation Addon 1.6 …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdt"` |
| `verified` | `bool` | 100% | Whether the exploit/finding was verified. | `true` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/zdt/1337DAY-ID-39943"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `424` |

