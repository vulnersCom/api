# `osv`  ·  ~940k documents

OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSV:MINI-5MGC-2RPC-7FV9"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T03:17:40"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T02:00:10"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T01:33:11"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T03:17:40.158000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"MINI-5MGC-2RPC-7FV9"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"osv"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/osv/OSV:MINI-5MGC-2RPC-7…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `library`-family document (typed by [`LibraryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Bulletin has no description"` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.9, "uncertanity": 2.0, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/MINI-5mgc-2rpc…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Google"` |

### Collection fields

Specific to the `osv` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "kube-apiserver-…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-7598"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "jordan@liggitt.net", …` |
| `metrics` | `object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "jordan@liggitt…` |
| `osvCrossReferences` | `list[object{key,references}]` | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["GO-2026-…` |
| `osvPackages` | `list[object{ecosystem,name,purl}]` | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "MinimOS", "name": "kube-apise…` |
| `purls` | `list[str]` | Affected packages as Package-URL (purl) strings. | `["pkg:apk/minimos/kube-apiserver-fips-1.33?di…` |

