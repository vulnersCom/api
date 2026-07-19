# Exceptions

Every error the SDK raises descends from `VulnersError`. See
[Error model](../explanation/error-model.md) for how a response is classified into one of
these.

```text
VulnersError
├── APIError                         # a request failed
│   ├── APIConnectionError           # no response (DNS/connect/read)
│   │   └── APITimeoutError          # timed out
│   ├── APIResponseValidationError   # 2xx body didn't match the schema
│   └── APIStatusError               # non-success status (or a 200 error envelope)
│       ├── BadRequestError          # 400
│       ├── AuthenticationError      # 401
│       ├── PermissionDeniedError    # 403
│       ├── NotFoundError            # 404
│       ├── ConflictError            # 409
│       ├── UnprocessableEntityError # 422
│       ├── RateLimitError           # 429  (inspect .retry_after)
│       └── InternalServerError      # 5xx
└── SearchWindowExceeded             # offset + limit > 10000  (also a ValueError)
```

::: vulners.VulnersError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.APIError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.APIStatusError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.APIConnectionError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.APITimeoutError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.APIResponseValidationError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.BadRequestError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.AuthenticationError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.PermissionDeniedError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.NotFoundError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.ConflictError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.UnprocessableEntityError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.RateLimitError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.InternalServerError
    options:
      heading_level: 2
      show_root_heading: true

::: vulners.SearchWindowExceeded
    options:
      heading_level: 2
      show_root_heading: true
