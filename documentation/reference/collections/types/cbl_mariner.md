# `cbl_mariner`  ·  ~14k documents

The CBL Mariner collection includes security advisories and CVEs specific to Microsoft's CBL Mariner Linux distribution.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Azure Linux", "OSVersion": "3.0", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58253"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.8, "uncertanity": 0.9, …` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CBLMARINER:92259"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T17:37:03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T01:38:21"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T01:38:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CBL Mariner"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T17:37:03.588000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cbl_mariner"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cbl_mariner/CBLMARINER:9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

