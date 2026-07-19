# The network & rate-limit model

This page explains how the v4 client talks to the API, so its defaults and knobs make sense.

## One client, one connection pool

A `Vulners` / `AsyncVulners` instance owns a single `httpx` client and its connection pool
(up to 1000 connections, 100 kept alive). Create **one** client and reuse it for the life of
your program; construct it as a context manager (`with` / `async with`) so the pool is
released on exit.

`with_options(...)` makes a cheap copy that **shares** the same pool while overriding
settings like `timeout` or `max_retries`, so per-call-site tuning does not open a second pool.

## Authentication

The API key is sent in the `X-Api-Key` header. It is held as a `SecretStr`, kept out of
object `repr`s and exception messages, and **stripped from the request on a cross-origin
redirect** so it is never forwarded to another host.

## Timeouts

There are two timeout profiles:

- **default** — connect 5s, read 60s, write 30s, pool 10s. Applied to normal requests.
- **archive** — read 300s. Applied automatically to bulk `archive` downloads, which can
  stream for a long time.

Override the default profile with the `timeout` argument (a number of seconds, or an
`httpx.Timeout`). See [Proxy, timeouts & retries](../how-to/proxy-timeout-retries.md).

## Retries

Transient failures are retried up to `max_retries` times (default 2): connection errors and
responses with status `429` or `5xx`. Backoff is exponential with jitter and honors a
`Retry-After` header when present. Separately, the transport retries the connection phase a
few times for DNS/connect blips.

## Rate limiting

Vulners advertises a per-key request budget in the `X-Vulners-Ratelimit-Reqlimit` response
header. The client runs a **token bucket** that adapts to this advertised limit and paces
outgoing requests so you stay under it, rather than firing requests and eating `429`s. If the
server does signal `429`, the request is retried after the indicated delay (bounded by an
internal cap, ~60s).

Because pacing is built in, the simplest correct usage — a loop over `search.query` or
`iter_query` — already respects your budget.

## Response-size guard

`max_response_bytes` (off by default) bounds how many decompressed bytes the client will read
from a response. Set it when pulling untrusted archives to defend against decompression
bombs.

It is `None` by default on purpose: Vulners archives are legitimately multi-gigabyte, so a
default cap would break normal downloads. That means **response decompression is unbounded
until you set `max_response_bytes`** — a tiny gzip/zip can inflate to many gigabytes. If you
point `base_url` at an untrusted or plain-HTTP on-prem host, set a cap so a malicious or
MITM'd response cannot exhaust memory.
