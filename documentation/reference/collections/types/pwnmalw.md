# `pwnmalw`  ·  ~46 documents

Pwnmalw is a collection from various security sources focused on malware advisories and exploits targeting multiple vendors and products.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Type: Flood Bots\n\nAuthor: [Xylitol](<https…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.5, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.pwnmalw.re/Http Botnets/vertexnet"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PWNMALW:VERTEXNET"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-03-15T07:30:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-01-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-01-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Xylitol"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"<code>#!/usr/bin/perl\n# VertexNet v1.1.1 Fl…` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-01-13T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Malware exploit: Vertexnet"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pwnmalw"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pwnmalw/PWNMALW:VERTEXNET"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `572` |

