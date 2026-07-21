# `cbl_mariner`  ·  ~14k documents

The CBL Mariner collection includes security advisories and CVEs specific to Microsoft's CBL Mariner Linux distribution.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-58253"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.8, "uncertanity": 0.9, …` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CBLMARINER:92259"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T17:37:03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T01:38:21"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T01:38:21"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CBL Mariner"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T17:37:03.588000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cbl_mariner"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cbl_mariner/CBLMARINER:9…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Azure Linux", "OSVersion": "3.0", "a…` |

### Collection fields

Specific to the `cbl_mariner` collection.

_None in the sample._

