# `pwnmalw`  ·  ~46 documents

Pwnmalw is a collection from various security sources focused on malware advisories and exploits targeting multiple vendors and products.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Type: Flood Bots\n\nAuthor: [Xylitol](<https…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.5, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.pwnmalw.re/Http Botnets/vertexnet"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PWNMALW:VERTEXNET"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-03-15T07:30:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2017-01-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2017-01-14T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Xylitol"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"<code>#!/usr/bin/perl\n# VertexNet v1.1.1 Fl…` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-01-13T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Malware exploit: Vertexnet"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pwnmalw"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/pwnmalw/PWNMALW:VERTEXNET"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `572` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `pwnmalw` collection.

_None in the sample._

