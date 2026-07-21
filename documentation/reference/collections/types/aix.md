# `aix`  ·  ~310 documents

AIX collection from IBM includes security advisories and CVEs specifically for the AIX operating system.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-2297", "CVE-2026-41080", "CVE-2026…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cna", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@python.org", "vers…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"IBM SECURITY ADVISORY\n\nFirst Issued: Tue J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 2.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-2297", "date": "2026-07-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://aix.software.ibm.com/aix/efixes/secu…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PYTHON_ADVISORY20.ASC"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:53:49"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "cna@python.org"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T06:03:19"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T06:03:19"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:53:50.189000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Multiple vulnerabilities in Python affect AIX"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"aix"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/aix/PYTHON_ADVISORY20.ASC"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `aix` collection.

| field | type | description | example |
|---|---|---|---|
| `aixFileset` | `list[object{fileset,productName,productVersions,versionGte,versionLte}]` | Affected AIX filesets (fileset, product, version). | `[{"productName": "aix", "productVersions": ["…` |

