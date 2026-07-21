# `w3af`  ·  ~140 documents

w3af is a vulnerability database focused on web application security, providing advisories, CVEs, and exploit information for various web technologies.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"W3AF:A65D96DB42BAA917B204B8164BD14CFE"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-03-12T23:34:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2019-09-07T16:11:05"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2017-11-22T18:51:21"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-11-22T15:51:21Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"xml_file"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"w3af"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/w3af/W3AF:A65D96DB42BAA9…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `58` |

### Family fields

Present in every sampled `scanner`-family document (typed by [`ScannerBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This plugin writes the framework messages to…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://w3af.org/plugins/output/xml_file"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"andresriancho"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"\"\"\"\nxml_file.py\n\nCopyright 2006 Andres…` |

### Collection fields

Specific to the `w3af` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `w3af` | `object{pluginType}` | w3af scanner provenance (plugin type). | `{"pluginType": "Output"}` |

