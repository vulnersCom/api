# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 4.x | ✅ |
| 3.2.x | ✅ (security fixes) |
| < 3.2 | ❌ |

## Reporting a vulnerability

Please report security issues in the SDK **privately** — do not open a public
issue or pull request for a vulnerability.

- Use GitHub's [private vulnerability reporting](https://github.com/vulnersCom/api/security/advisories/new)
  (Security → Report a vulnerability), or
- contact the Vulners team through [vulners.com](https://vulners.com).

Please include a description, affected version(s), and a minimal reproduction.
We aim to acknowledge reports within a few business days and will keep you
updated on the fix and disclosure timeline.

## Scope

This policy covers the `vulners` Python package in this repository. Issues in
the Vulners web service or API itself should be reported through
[vulners.com](https://vulners.com).

## How the SDK protects your API key

The client is designed to keep your credential out of places it could leak:

- the key is sent only in the `X-Api-Key` request header (never logged);
- it is stripped from any request that is redirected to a different origin, and
  redirects to private/internal/loopback addresses are refused (SSRF guard);
- it is masked in exception messages, object `repr()`, and debug logs;
- `Set-Cookie` from responses is dropped so no session state is retained.

An opt-in `max_response_bytes` limit bounds in-memory buffering and archive
decompression to guard against decompression-bomb responses.
