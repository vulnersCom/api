# `w3af`  ·  ~140 documents

w3af is a vulnerability database focused on web application security, providing advisories, CVEs, and exploit information for various web technologies.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This plugin writes the framework messages to…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://w3af.org/plugins/output/xml_file"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"W3AF:A65D96DB42BAA917B204B8164BD14CFE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-03-12T23:34:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-09-07T16:11:05"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-11-22T18:51:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"andresriancho"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"\"\"\"\nxml_file.py\n\nCopyright 2006 Andres…` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-11-22T15:51:21Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"xml_file"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"w3af"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/w3af/W3AF:A65D96DB42BAA9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `58` |
| `w3af` | `object{pluginType}` | 100% | w3af scanner provenance (plugin type). | `{"pluginType": "Output"}` |

