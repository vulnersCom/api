# Resources

Each namespace on the client (`v.search`, `v.audit`, …) is a resource. The classes below are
the **synchronous** resources; the async client exposes an `Async*` mirror of each, with the
same non-iterator methods as awaitable coroutines. The auto-paginating streaming iterators are
renamed with an `a` prefix (`aiter_query`, `aiter_collection`) and are async generators consumed
with `async for`, not coroutines.

## Search

::: vulners._resources._sync.search.Search
    options:
      heading_level: 3
      show_root_heading: true

## Documents

::: vulners._resources._sync.documents.Documents
    options:
      heading_level: 3
      show_root_heading: true

## Audit

::: vulners._resources._sync.audit.Audit
    options:
      heading_level: 3
      show_root_heading: true

## Archive

::: vulners._resources._sync.archive.Archive
    options:
      heading_level: 3
      show_root_heading: true

## Misc

::: vulners._resources._sync.misc.Misc
    options:
      heading_level: 3
      show_root_heading: true

## Report

::: vulners._resources._sync.report.Report
    options:
      heading_level: 3
      show_root_heading: true

## Stix

::: vulners._resources._sync.stix.Stix
    options:
      heading_level: 3
      show_root_heading: true

## Subscriptions

::: vulners._resources._sync.subscriptions.Subscriptions
    options:
      heading_level: 3
      show_root_heading: true

## SubscriptionsV4

::: vulners._resources._sync.subscriptions_v4.SubscriptionsV4
    options:
      heading_level: 3
      show_root_heading: true

## Webhooks

::: vulners._resources._sync.webhooks.Webhooks
    options:
      heading_level: 3
      show_root_heading: true

## VScanner

::: vulners._resources._sync.vscanner.Vscanner
    options:
      heading_level: 3
      show_root_heading: true

The `Vscanner` namespace delegates to nested resources for project and license operations
(`v.vscanner.projects`, `v.vscanner.licenses`); task and result operations are nested under a
project (`v.vscanner.projects.tasks`, `v.vscanner.projects.results`):

::: vulners._resources._sync.vscanner.VscannerProjects
    options:
      heading_level: 3
      show_root_heading: true

::: vulners._resources._sync.vscanner.VscannerTasks
    options:
      heading_level: 3
      show_root_heading: true

::: vulners._resources._sync.vscanner.VscannerResults
    options:
      heading_level: 3
      show_root_heading: true

::: vulners._resources._sync.vscanner.VscannerLicenses
    options:
      heading_level: 3
      show_root_heading: true
