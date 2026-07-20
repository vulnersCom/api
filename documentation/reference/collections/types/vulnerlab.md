# `vulnerlab`  ·  ~3.4k documents

VulnerLab provides advisories and CVEs focused on various software products and vulnerabilities, sourced from community contributions and research.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `category` | `str` | 100% | Category assigned by the source. | `"Website Vulnerabilities"` |
| `cvelist` | `list[str]` | 5% | Related CVE identifiers referenced by this document. | `["CVE-2023-3786"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}` | 5% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.4, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-3786", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.vulnerability-lab.com/get_conten…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNERABLE:2327"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-09-25T13:33:56"` |
| `metrics` | `object{cna,nvd}` | 5% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-07-25T00:00:00"` |
| `price` | `object{EUR}` | 100% | Exploit price (for commercial exploit feeds). | `{"EUR": "1000-2000"}` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-07-25T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"L. Guenther - https://www.vulnerability-lab.…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"Document Title:\r\n===============\r\nETSI W…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-07-24T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ETSI WEBstore 2023 - Persistent Cross Site V…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnerlab"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnerlab/VULNERABLE:2327"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `407` |

