# Data models

Every document Vulners returns is a **bulletin**, modelled in three inheritance layers so you get typed fields and IDE hints at whatever level of detail you need:

1. **[`Bulletin`](base.md)** — the base: the fields every document carries.
2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per `bulletinFamily`, extending `Bulletin` with that family's shared fields.
3. **Collection models** — one per collection `type`, extending its family model with the fields specific to that collection.

`search`/`archive`/`audit` return the most specific model that matches a document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model keeps `extra="allow"`, so a field Vulners adds before the SDK models it is still there on the object, just untyped — nothing is ever dropped.

> A field sits at the level where it is always present: on `Bulletin` when every document carries it, on a family model when every document of that `bulletinFamily` carries it, otherwise on the collection model.

## Structure

`Bulletin` (base) → a model per `bulletinFamily` → a model per collection `type`. Every family model extends `Bulletin`; every collection model extends its family model, so `isinstance` holds at every level (a `nessus` document is a `NessusBulletin`, which is a `ScannerBulletin`, which is a `Bulletin`). Each family below links to its page, which lists the family's fields and every collection type under it.

- **[`Bulletin`](base.md)** — base fields, common to every document
    - **[`BlogBulletin`](blog.md)** — `bulletinFamily: blog`
    - **[`BugbountyBulletin`](bugbounty.md)** — `bulletinFamily: bugbounty`
    - **[`CnnvdBulletin`](cnnvd.md)** — `bulletinFamily: cnnvd`
    - **[`CnvdBulletin`](cnvd.md)** — `bulletinFamily: cnvd`
    - **[`CryptoBulletin`](crypto.md)** — `bulletinFamily: crypto`
    - **[`CveBulletin`](cve.md)** — `bulletinFamily: cve`
    - **[`EuvdBulletin`](euvd.md)** — `bulletinFamily: euvd`
    - **[`ExploitBulletin`](exploit.md)** — `bulletinFamily: exploit`
    - **[`InfoBulletin`](info.md)** — `bulletinFamily: info`
    - **[`JvnBulletin`](jvn.md)** — `bulletinFamily: jvn`
    - **[`LibraryBulletin`](library.md)** — `bulletinFamily: library`
    - **[`MicrosoftBulletin`](microsoft.md)** — `bulletinFamily: microsoft`
    - **[`NcscBulletin`](ncsc.md)** — `bulletinFamily: ncsc`
    - **[`NozomiBulletin`](nozomi.md)** — `bulletinFamily: nozomi`
    - **[`ScannerBulletin`](scanner.md)** — `bulletinFamily: scanner`
    - **[`SoftwareBulletin`](software.md)** — `bulletinFamily: software`
    - **[`ToolsBulletin`](tools.md)** — `bulletinFamily: tools`
    - **[`UnixBulletin`](unix.md)** — `bulletinFamily: unix`

## Base fields

Present in every document, at the `Bulletin` level — full table with types, descriptions and examples on **[the base page](base.md)**:

`bulletinFamily`, `cvelist`, `cvss`, `cvss2`, `cvss3`, `cvss4`, `description`, `enchantments`, `epss`, `href`, `id`, `immutableFields`, `lastseen`, `metrics`, `modified`, `published`, `references`, `reporter`, `sourceAvailable`, `timestamps`, `title`, `type`, `vendorId`, `vhref`, `viewCount`

