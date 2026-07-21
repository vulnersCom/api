# `osv`  ·  ~940k documents

OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-39892"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "osv", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Root has patched GHSA-537c-gmf6-5ccf in the …` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39892", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/ROOT-APP-PYPI-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSV:ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:14:01"` |
| `metrics` | `object{adp,cna}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "osv", "vers…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T06:45:05"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T05:48:27"` |
| `references` | `list[str]` | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T20:08:52.852000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF GHSA-537c-…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"osv"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/osv/OSV:ROOT-APP-PYPI-GH…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`LibraryBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "pypi", "name": "vantrala", "ve…` |
| `purls` | `list[str]` | Affected packages as Package-URL (purl) strings. | `["pkg:pypi/vantrala"]` |

### Collection fields

Specific to the `osv` collection.

| field | type | description | example |
|---|---|---|---|
| `osvCrossReferences` | `list[object{key,references}]` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["GHSA-537…` |
| `osvPackages` | `list[object{ecosystem,name,purl}], list[object{ecosystem,name}]` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Root:PyPI", "name": "rootio-c…` |
| `osvSeverity` | `list[object{score,type}]` | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |

