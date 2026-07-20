# `n0where`  ·  ~1.1k documents

n0where is a vulnerability database focusing on advisories and CVEs related to various software products and operating systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: tools`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Ghidra is a software reverse engineering (SR…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": -0.0, "vector": "NONE"}, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://n0where.net/nsa-software-reverse-eng…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"N0WHERE:173110"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-03-06T07:51:59"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-03-06T03:58:08"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-03-06T03:58:08"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/GoVanguard/legion/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"N0where"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-03-06T00:58:08Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"NSA Software Reverse Engineering Framework: …` |
| `toolHref` | `str` | 100% | Link to the associated tool/exploit. | `"https://ghidra-sre.org/"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"n0where"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/n0where/N0WHERE:173110"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `234` |

