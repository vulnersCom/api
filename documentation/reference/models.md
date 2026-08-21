# Models & pagination

## Bulletins

Search and lookup methods return `Bulletin` objects. The most specific model is chosen for
each document: a known collection `type` selects a per-collection model, otherwise the
`bulletinFamily` selects a family model, falling back to `GenericBulletin`. Per-collection
models subclass their family model, which subclasses `Bulletin`, so family classes are a
stable `isinstance`/annotation surface. Fields are accessed as attributes and are all optional
(a missing field is `None`).

The family and per-collection models follow a `base → family → type` hierarchy — see
**[Data models](bulletins/index.md)** for every family and collection with its fields,
descriptions and examples.

::: vulners._models.bulletin.Bulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.GenericBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

### CVSS & nested objects

Value objects shared across families. `Cvss` specializes to `Cvss2`/`Cvss3`/`Cvss4`
by its `version`.

::: vulners._models.bulletin.Cvss
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.Timestamps
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.Enchantments
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.EpssScore
    options:
      heading_level: 4
      show_root_heading: true
      members: []

## Package metadata

`audit.metadata` returns a `PackageMetadata`: a package's declared `license` (always a list),
its `version` and the `range` the metadata covers. Use `found` to tell a package the registry
does not know (empty `range`) apart from a known package with no recorded license.

::: vulners._models.audit.PackageMetadata
    options:
      heading_level: 3
      show_root_heading: true

## Pagination

`search.query` returns a `SearchPage` (async: `AsyncSearchPage`). It knows its place in the
result window and walks further pages when you iterate it.

::: vulners._pagination.SearchPage
    options:
      heading_level: 3
      show_root_heading: true

::: vulners._pagination.AsyncSearchPage
    options:
      heading_level: 3
      show_root_heading: true

## Client configuration

The resolved, immutable configuration for a client instance is available as `client.config`.

::: vulners._config.ClientConfig
    options:
      heading_level: 3
      show_root_heading: true
