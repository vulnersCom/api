# `osv`  ·  ~940k documents

OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,versionStartIncluding}]` | 90% | Affected libraries/packages (name, purl, version range). | `[{"registry": "pypi", "name": "vantrala", "ve…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[str]` | 15% | Related CVE identifiers referenced by this document. | `["CVE-2026-39892"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 15% | CVSS v3.x score block. | `{"cvssV31": {"source": "osv", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Root has patched GHSA-537c-gmf6-5ccf in the …` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39892", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/ROOT-APP-PYPI-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSV:ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:14:01"` |
| `metrics` | `object{adp,cna}, object{vendor}` | 15% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "osv", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T06:45:05"` |
| `osvCrossReferences` | `list[object{key,references}]` | 80% | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["GHSA-537…` |
| `osvPackages` | `list[object{ecosystem,name,purl}], list[object{ecosystem,name}]` | 100% | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Root:PyPI", "name": "rootio-c…` |
| `osvSeverity` | `list[object{score,type}]` | 5% | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:48:27"` |
| `purls` | `list[str]` | 90% | Affected packages as Package-URL (purl) strings. | `["pkg:pypi/vantrala"]` |
| `references` | `list[str]` | 80% | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T20:08:52.852000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF GHSA-537c-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"osv"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/osv/OSV:ROOT-APP-PYPI-GH…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

