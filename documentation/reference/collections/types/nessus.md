# `nessus`  ·  ~340k documents

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cpe` | `list[str]` | 100% | Affected products as CPE 2.2 URIs. | `["cpe:/o:fedoraproject:fedora:43", "p-cpe:/a:…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53689"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvssScoreSource` | `str` | 100% | Which party/standard the CVSS score was taken from. | `"CVE-2026-53689"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The remote Fedora 43 host has packages insta…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `exploitAvailable` | `bool` | 100% | Whether a public exploit is available. | `false` |
| `exploitEase` | `str` | 100% | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.tenable.com/plugins/nessus/327807"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FEDORA_2026-8893EC1AEB.NASL"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:58:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `naslFamily` | `str` | 100% | Nessus NASL plugin family. | `"Fedora Local Security Checks"` |
| `nessusSeverity` | `str` | 100% | Severity as rated by the Nessus scanner. | `"High"` |
| `patchPublicationDate` | `str` | 100% | Date the fixing patch was published. | `"2026-07-10T00:00:00"` |
| `pluginID` | `str` | 100% | Scanner plugin identifier (e.g. Nessus plugin id). | `"327807"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bodhi.fedoraproject.org/updates/FED…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Tenable"` |
| `solution` | `str` | 100% | Recommended remediation/fix, as text. | `"Update the affected python-uv-build, rust-as…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T01:58:55.970000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Fedora 43 : python-uv-build / rust-astral_as…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nessus"` |
| `vendor_cvss2` | `object{score,vector}` | 100% | Vendor-assigned CVSS v2 (score/vector). | `{"score": null, "vector": null}` |
| `vendor_cvss3` | `object{score,vector}` | 100% | Vendor-assigned CVSS v3 (score/vector). | `{"score": null, "vector": null}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nessus/FEDORA_2026-8893E…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |
| `vulnerabilityPublicationDate` | `str` | 100% | Date the vulnerability itself was first published. | `"2026-07-10T00:00:00"` |

