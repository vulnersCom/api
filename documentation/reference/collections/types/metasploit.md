# `metasploit`  ·  ~7.3k documents

Metasploit collection includes exploit modules and payloads for various vulnerabilities, primarily targeting software and systems across multiple platforms.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This module supports running an HTTP server …` |
| `enchantments` | `object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.rapid7.com/db/modules/auxiliary/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSF:AUXILIARY-SERVER-RELAY-HTTP_TO_SMB-"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:40:16"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T19:06:26"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T19:06:26"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"jheysel-r7"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 65% | Raw, unparsed source body as delivered by the origin. | `"# frozen_string_literal: true\n\n##\n# This …` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://github.com/rapid7/metasploit-framewo…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:40:20.867000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Windows HTTP to SMB Relay"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"metasploit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/metasploit/MSF:AUXILIARY…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `56` |

