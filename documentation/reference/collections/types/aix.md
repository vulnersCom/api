# `aix`  ·  ~310 documents

AIX collection from IBM includes security advisories and CVEs specifically for the AIX operating system.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `aixFileset` | `list[object{fileset,productName,productVersions,versionGte,versionLte}]` | 100% | Affected AIX filesets (fileset, product, version). | `[{"productName": "aix", "productVersions": ["…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2297", "CVE-2026-41080", "CVE-2026…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"IBM SECURITY ADVISORY\n\nFirst Issued: Tue J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-2297", "date": "2026-07-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://aix.software.ibm.com/aix/efixes/secu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PYTHON_ADVISORY20.ASC"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:53:49"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "cna@python.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T06:03:19"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T06:03:19"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:53:50.189000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Multiple vulnerabilities in Python affect AIX"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"aix"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/aix/PYTHON_ADVISORY20.ASC"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

