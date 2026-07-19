# The error model

Every failure raises a subclass of `VulnersError`; the full tree is in the
[exceptions reference](../reference/exceptions.md). This page explains **how** a response
becomes a particular exception.

## Two axes: error code first, then HTTP status

A failed response is classified in two steps:

1. **Vulners `errorCode`** — when the body carries one, a small curated map picks the class
   (e.g. a "missing/invalid parameter" code → `BadRequestError`).
2. **HTTP status** — otherwise the status decides: `401 → AuthenticationError`,
   `403 → PermissionDeniedError`, `404 → NotFoundError`, `409 → ConflictError`,
   `422 → UnprocessableEntityError`, `429 → RateLimitError`, `5xx → InternalServerError`,
   other `4xx → BadRequestError`.

## Errors can arrive with HTTP 200

The Vulners API sometimes returns a business error inside an HTTP **200** response — a v3
envelope like `{"result": "error", "data": {"error": ..., "errorCode": ...}}`. The client
checks for these error markers **before** trusting the status, so a 200-wrapped error becomes
a real exception instead of being handed back as data.

## What an error carries

`APIError` (and its subclasses) expose:

| Attribute | Meaning |
|---|---|
| `status_code` | HTTP status, or `None` for a client-side/transport failure |
| `error_code` | the Vulners `errorCode`, when the body had one |
| `message` | the server's human-readable problem description |
| `data` | the full error payload, **with API-key material redacted** |
| `retry_after` | parsed `Retry-After` hint in seconds (mainly on `RateLimitError`) |

```python
from vulners import Vulners, RateLimitError, APIStatusError

with Vulners() as v:
    try:
        v.search.query("type:cve")
    except RateLimitError as err:
        wait = err.retry_after or 5.0
        ...
    except APIStatusError as err:
        print(err.status_code, err.error_code, err.message)
```

## Transport and validation failures

- `APIConnectionError` — the request never got a response (DNS, connect, or read failure);
  `status_code` is `None`. `APITimeoutError` is the timed-out subclass.
- `APIResponseValidationError` — a 2xx body did not match what the endpoint promised.

## Redaction

Before an error payload is attached to an exception (and thus potentially logged), any field
that names credential material (`apiKey`, `X-Api-Key`) is replaced with `[REDACTED]`, and the
known key value is masked anywhere it appears. Logging an exception never leaks your key.
