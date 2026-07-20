# `srcincite`  ·  ~290 documents

SrcIncite provides vulnerability advisories and CVEs focused on various software products and services, sourced from multiple security vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-25202"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Vulnerability Details:**\n\nThis vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-25202", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://srcincite.io/advisories/src-2025-0006/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SRC-2025-0006"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-28T22:49:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@samsung.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-28T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-09-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Steven Seeley of Source Incite"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"#!/usr/bin/env python3\n\"\"\"\nSamsung Magi…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://srcincite.io/pocs/src-2025-0006.py.txt"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-29T04:06:30.344000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SRC-2025-0006 : Samsung MagicINFO 9 Server M…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"srcincite"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/srcincite/SRC-2025-0006"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `151` |

