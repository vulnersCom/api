# Data models

Every document Vulners returns is a **bulletin**, modelled in three layers so you get typed fields and IDE hints at whatever level of detail you need:

1. **[`Bulletin`](base.md)** — the base: the fields every document carries.
2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per `bulletinFamily`, adding that family's shared fields.
3. **Collection models** — one per collection `type`, adding the fields specific to that collection.

`search`/`archive`/`audit` return the most specific model that matches a document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model keeps `extra="allow"`, so a field Vulners adds before the SDK models it is still there on the object, just untyped — nothing is ever dropped.

> The models **and** these pages are generated from live samples by `dev-tools/data-models/sample_collections.py`; a field belongs to a layer when the server sends it in *every* sampled document at that level.

## Families (18)

| family | model | collections |
|---|---|---|
| [`blog`](blog.md) | `BlogBulletin` | 35 |
| [`bugbounty`](bugbounty.md) | `BugbountyBulletin` | 4 |
| [`cnnvd`](cnnvd.md) | `CnnvdBulletin` | 1 |
| [`cnvd`](cnvd.md) | `CnvdBulletin` | 1 |
| [`crypto`](crypto.md) | `CryptoBulletin` | 1 |
| [`cve`](cve.md) | `CveBulletin` | 5 |
| [`euvd`](euvd.md) | `EuvdBulletin` | 1 |
| [`exploit`](exploit.md) | `ExploitBulletin` | 18 |
| [`info`](info.md) | `InfoBulletin` | 40 |
| [`jvn`](jvn.md) | `JvnBulletin` | 1 |
| [`library`](library.md) | `LibraryBulletin` | 3 |
| [`microsoft`](microsoft.md) | `MicrosoftBulletin` | 3 |
| [`ncsc`](ncsc.md) | `NcscBulletin` | 1 |
| [`nozomi`](nozomi.md) | `NozomiBulletin` | 1 |
| [`scanner`](scanner.md) | `ScannerBulletin` | 5 |
| [`software`](software.md) | `SoftwareBulletin` | 82 |
| [`tools`](tools.md) | `ToolsBulletin` | 2 |
| [`unix`](unix.md) | `UnixBulletin` | 34 |

