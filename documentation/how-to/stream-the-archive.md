# How to stream and sync the archive

The `archive` resource downloads bulk collections of the Vulners database — useful for
seeding a local mirror or a data pipeline. Collections can be **gigabytes**, so these calls
use a longer timeout profile automatically.

## Download a whole collection

`fetch_collection` buffers and decodes the entire archive in memory. Good for small-to-
medium collections:

=== "Sync"

    ```python
    from vulners import Vulners

    with Vulners() as v:
        cve_docs = v.archive.fetch_collection("cve")
        print(type(cve_docs))   # parsed JSON when the body is a single document
    ```

=== "Async"

    ```python
    from vulners import AsyncVulners

    async with AsyncVulners() as v:
        cve_docs = await v.archive.fetch_collection("cve")
        print(type(cve_docs))   # parsed JSON when the body is a single document
    ```

## Stream a large collection record by record

For big collections, `iter_collection` (async: `aiter_collection`) follows the archive
redirect to storage and yields each record lazily, so the whole archive never has to be
held in memory:

=== "Sync"

    ```python
    from vulners import Vulners

    with Vulners() as v:
        count = 0
        for record in v.archive.iter_collection("cve"):
            count += 1            # process one document at a time
        print(count, "records")
    ```

=== "Async"

    ```python
    import asyncio
    from vulners import AsyncVulners

    async def main() -> None:
        async with AsyncVulners() as v:
            count = 0
            async for record in v.archive.aiter_collection("cve"):
                count += 1        # process one document at a time
            print(count, "records")

    asyncio.run(main())
    ```

!!! tip "Fast decoding is built in"
    Archive decode is ISA-L accelerated (`isal`) and multi-member zip streaming
    (`stream-unzip`) works out of the box — both ship with the core package, no extra needed.

## Download an archive to disk in parallel

When you want the raw archive **on disk** as fast as possible (to seed a mirror, or for the
getsploit SQLite database), `download_collection` and `download_getsploit` pull the archive over
several HTTP range connections at once and write each chunk straight to its offset in the file.
The link is saturated, memory stays constant, and the write is **atomic** — an interrupted
download never clobbers an existing file. If the storage does not offer range requests, both
transparently fall back to a single stream.

=== "Sync"

    ```python
    from vulners import Vulners

    with Vulners() as v:
        # A whole collection archive (still compressed) straight to disk:
        n = v.archive.download_collection("cve", "cve.archive", connections=8)
        print(n, "bytes written")

        # The getsploit exploit database (a single-member zip of getsploit.db):
        v.archive.download_getsploit("getsploit.db.zip", connections=8)
    ```

=== "Async"

    ```python
    from vulners import AsyncVulners

    async with AsyncVulners() as v:
        n = await v.archive.download_collection("cve", "cve.archive", connections=8)
        print(n, "bytes written")
        await v.archive.download_getsploit("getsploit.db.zip", connections=8)
    ```

`connections` is the number of parallel range connections (default 8). To keep an existing mirror
current, pass `update_from` to `download_collection` to fetch only the changed entries.

!!! tip "Maximum throughput"
    The SDK-owned client transfers the ranges over a dedicated **HTTP/1.1** connection pool so each
    connection opens a real socket and saturates the link (HTTP/2 would multiplex every range onto a
    single connection). If you bring your own `http_client`, pass `http2=False` on it for the same
    benefit.

## Sync only what changed

To keep a mirror up to date, fetch just the entries changed since your last sync with
`fetch_collection_update` and a timezone-aware `datetime`:

=== "Sync"

    ```python
    from datetime import datetime, timezone
    from vulners import Vulners

    with Vulners() as v:
        delta = v.archive.fetch_collection_update(
            "cve",
            after=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
    ```

=== "Async"

    ```python
    from datetime import datetime, timezone
    from vulners import AsyncVulners

    async with AsyncVulners() as v:
        delta = await v.archive.fetch_collection_update(
            "cve",
            after=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
    ```

## Guard against untrusted decompression

Archives are compressed. To bound how many bytes the client will decompress (a defense
against decompression bombs), set `max_response_bytes` on the client:

=== "Sync"

    ```python
    with Vulners(max_response_bytes=2 * 1024**3) as v:   # cap at 2 GiB
        v.archive.fetch_collection("cve")
    ```

=== "Async"

    ```python
    async with AsyncVulners(max_response_bytes=2 * 1024**3) as v:   # cap at 2 GiB
        await v.archive.fetch_collection("cve")
    ```
