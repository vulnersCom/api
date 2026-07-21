# `metasploit`  ·  ~7.3k documents

Metasploit collection includes exploit modules and payloads for various vulnerabilities, primarily targeting software and systems across multiple platforms.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSF:AUXILIARY-SERVER-RELAY-HTTP_TO_SMB-"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:40:16"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T19:06:26"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T19:06:26"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:40:20.867000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft Windows HTTP to SMB Relay"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"metasploit"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/metasploit/MSF:AUXILIARY…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `56` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |

### Collection fields

Specific to the `metasploit` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This module supports running an HTTP server …` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.rapid7.com/db/modules/auxiliary/…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"jheysel-r7"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"# frozen_string_literal: true\n\n##\n# This …` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://github.com/rapid7/metasploit-framewo…` |

