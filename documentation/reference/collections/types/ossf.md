# `ossf`  ·  ~230k documents

OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n---\n_-= Per source details. Do not edit b…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.4, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/ossf/malicious-packages/b…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSF:MAL-2026-10867"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:38:26"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:19:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:19:03"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OSSF Malicious Packages"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:38:26.420000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Malicious code in vantrala (PyPI)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossf"` |
| `vendorId` | `str` | 100% | Vendor's own identifier for the advisory, when provided. | `"MAL-2026-10867"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ossf/OSSF:MAL-2026-10867"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

