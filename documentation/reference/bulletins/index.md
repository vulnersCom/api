# Data models

Every document Vulners returns is a **bulletin**, modelled in three inheritance layers so you get typed fields and IDE hints at whatever level of detail you need:

1. **[`Bulletin`](base.md)** — the base: the fields every document carries.
2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per `bulletinFamily`, extending `Bulletin` with that family's shared fields.
3. **Collection models** — one per collection `type`, extending its family model with the fields specific to that collection.

`search`/`archive`/`audit` return the most specific model that matches a document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model keeps `extra="allow"`, so a field Vulners adds before the SDK models it is still there on the object, just untyped — nothing is ever dropped.

> The models **and** these pages are generated from live samples by `dev-tools/data-models/sample_collections.py` into `src/vulners/_models/bulletins/` (one file per family); a field belongs to a layer when the server sends its key in *every* sampled document at that level.

## Structure

`Bulletin` (base) → 18 family models → 238 collection models. Every family model extends `Bulletin`; every collection model extends its family model, so `isinstance` holds at every level (a `nessus` document is a `NessusBulletin`, which is a `ScannerBulletin`, which is a `Bulletin`). Each row links to that family's page, listing its fields and every collection type under it.

- **[`Bulletin`](base.md)** — base · 25 common fields
    - **[`BlogBulletin`](blog.md)** — `bulletinFamily: blog` · +0 fields · 35 collection types
    - **[`BugbountyBulletin`](bugbounty.md)** — `bulletinFamily: bugbounty` · +1 field · 4 collection types
    - **[`CnnvdBulletin`](cnnvd.md)** — `bulletinFamily: cnnvd` · +3 fields · 1 collection type
    - **[`CnvdBulletin`](cnvd.md)** — `bulletinFamily: cnvd` · +4 fields · 1 collection type
    - **[`CryptoBulletin`](crypto.md)** — `bulletinFamily: crypto` · +1 field · 1 collection type
    - **[`CveBulletin`](cve.md)** — `bulletinFamily: cve` · +1 field · 5 collection types
    - **[`EuvdBulletin`](euvd.md)** — `bulletinFamily: euvd` · +2 fields · 1 collection type
    - **[`ExploitBulletin`](exploit.md)** — `bulletinFamily: exploit` · +0 fields · 18 collection types
    - **[`InfoBulletin`](info.md)** — `bulletinFamily: info` · +0 fields · 40 collection types
    - **[`JvnBulletin`](jvn.md)** — `bulletinFamily: jvn` · +3 fields · 1 collection type
    - **[`LibraryBulletin`](library.md)** — `bulletinFamily: library` · +1 field · 3 collection types
    - **[`MicrosoftBulletin`](microsoft.md)** — `bulletinFamily: microsoft` · +2 fields · 3 collection types
    - **[`NcscBulletin`](ncsc.md)** — `bulletinFamily: ncsc` · +3 fields · 1 collection type
    - **[`NozomiBulletin`](nozomi.md)** — `bulletinFamily: nozomi` · +3 fields · 1 collection type
    - **[`ScannerBulletin`](scanner.md)** — `bulletinFamily: scanner` · +1 field · 5 collection types
    - **[`SoftwareBulletin`](software.md)** — `bulletinFamily: software` · +0 fields · 82 collection types
    - **[`ToolsBulletin`](tools.md)** — `bulletinFamily: tools` · +1 field · 2 collection types
    - **[`UnixBulletin`](unix.md)** — `bulletinFamily: unix` · +0 fields · 34 collection types

## Base fields (25)

Present in every document, at the `Bulletin` level — full table with types, descriptions and examples on **[the base page](base.md)**:

`bulletinFamily`, `cvelist`, `cvss`, `cvss2`, `cvss3`, `cvss4`, `description`, `enchantments`, `epss`, `href`, `id`, `immutableFields`, `lastseen`, `metrics`, `modified`, `published`, `references`, `reporter`, `sourceAvailable`, `timestamps`, `title`, `type`, `vendorId`, `vhref`, `viewCount`

