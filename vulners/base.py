from __future__ import annotations

import re
import sys
import zlib
from collections import defaultdict
from functools import wraps
from importlib.metadata import version
from time import sleep, time
from typing import Any, Callable, ClassVar, Literal, Mapping

import httpx
import orjson
from pydantic import ConfigDict, create_model
from pydantic.fields import FieldInfo
from typing_inspection import introspection

__version__ = version("vulners")


class VulnersApiError(Exception):
    def __init__(self, http_status, data):
        super(VulnersApiError, self).__init__(data)
        self.http_status = http_status


class RateLimitBucket:
    """An implementation of the Token Bucket algorithm."""

    def __init__(self, rate=10.0, burst=1.0):
        self._rate = float(rate)
        self._burst = min(float(burst), self._rate)
        self._allowance = self._burst
        self._last_check = time()

    def update(self, rate, burst=1.0):
        self._rate = float(rate)
        self._burst = min(float(burst), self._rate)

    def consume(self):
        while 1:
            now = time()
            # number of seconds since the last call
            delta = now - self._last_check
            self._last_check = now
            # increase the number of allowed calls
            self._allowance += delta * self._rate
            if self._allowance > self._burst:
                # don't allow more than "burst" calls
                self._allowance = self._burst
            if self._allowance < 1:
                # cold down
                sleep((1 - self._allowance) / self._rate)
                continue
            self._allowance -= 1
            break


class VulnersApiTransport(httpx.BaseTransport):
    def __init__(self, transport: httpx.BaseTransport):
        self.transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.transport.handle_request(request)
        if "set-cookie" in response.headers:
            del response.headers["set-cookie"]
        return response


class VulnersApiBase:
    _ratelimits: dict[str, RateLimitBucket] = defaultdict(RateLimitBucket)

    _ratelimit_key: ClassVar[str] = ""

    def __init__(
        self,
        api_key: str,
        proxy: str | None = None,
        *,
        retry_count: int = 3,
        server_url: str = "https://vulners.com",
    ):
        """
        Create API.

        :param api_key:
            Vulners API key. You can get one from https://vulners.com
        :param proxy:
            Proxy url, example: "https://myproxy.com:3128"
        """
        if not api_key:
            raise ValueError(
                "API key must be provided. You can obtain one for free at https://vulners.com"
            )

        if not isinstance(api_key, str):
            raise TypeError("api_key parameter must be a string value")

        self._client = httpx.Client(
            follow_redirects=True,
            base_url=server_url,
            transport=VulnersApiTransport(httpx.HTTPTransport(proxy=proxy, retries=retry_count)),
            headers={
                "User-Agent": "Vulners Python API %s" % __version__,
                "X-Api-Key": api_key,
            },
        )
        self._api_key = api_key

    def _send_request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
        url: str,
        params: dict[str, Any],
        path_params: tuple[str, ...],
        add_api_key: bool,
    ):
        if path_params:
            url = re.sub("{([^}]*)}", lambda m: str(params.pop(m.group(1))), url)
        if add_api_key:
            params["apiKey"] = self._api_key
        kwargs: dict[str, Any] = {"params" if method in ("GET", "DELETE") else "json": params}
        bucket = self._ratelimits[self._ratelimit_key or url]
        bucket.consume()
        response = self._client.request(method, url, **kwargs)
        self._update_ratelimit(bucket, response)
        return response

    @staticmethod
    def _handle_response(response: httpx.Response) -> Any:
        if response.headers["content-type"] == "application/json":
            if response.content:
                result = orjson.loads(response.content)
            else:
                result = None
            if isinstance(result, dict) and "data" in result:
                data = result["data"]
                if isinstance(data, dict) and data.get("error"):
                    raise VulnersApiError(response.status_code, data)
                return data
            if response.status_code >= 400:
                raise VulnersApiError(response.status_code, result)
            return result
        elif response.headers["content-type"] == "application/x-gzip-compressed":
            return orjson.loads(zlib.decompress(response.content))
        else:
            return response.content

    @staticmethod
    def _update_ratelimit(bucket, response):
        headers = response.headers
        limit = headers.get("X-Vulners-Ratelimit-Reqlimit")
        if limit:
            try:
                limit = float(limit) / 60.0
            except (TypeError, ValueError):
                return
            bucket.update(rate=limit)


def _ann_repr(t: Any) -> str:
    if isinstance(t, type):
        if t.__module__ != "builtins":
            return f"{t.__module__}.{t.__name__}"
        return t.__name__
    return repr(t)


def endpoint(
    name: str,
    /,
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
    url: str,
    description: str | None = None,
    params: Mapping[str, Any] | None = None,
    response_handler: Callable[[Any], Any] | None = None,
    wrapper: Any = None,
    add_api_key: bool = False,
) -> Callable[..., Any]:
    assert method in ("GET", "POST", "PUT", "DELETE", "PATCH")
    assert isinstance(url, str)
    assert description is None or isinstance(description, str)
    assert params is None or isinstance(params, Mapping)

    parent_namespace = sys._getframe(1).f_globals
    params = params or {}

    path_params = tuple(re.findall("{([^}]*)}", url))
    for param in path_params:
        assert param in params

    if wrapper is not None:
        returns = f"{wrapper.__module__}.{wrapper.__name__}"
    else:
        returns = "dict[str, typing.Any]"

    func_args = []
    for param, param_type in params.items():
        ann = introspection.inspect_annotation(
            param_type, annotation_source=introspection.AnnotationSource.FUNCTION
        )
        if (
            ann.metadata
            and isinstance(ann.metadata[0], FieldInfo)
            and not ann.metadata[0].is_required()
        ):
            func_args.append(f"{param}: {_ann_repr(ann.type)} = {ann.metadata[0].default!r}")
        else:
            func_args.append(f"{param}: {_ann_repr(ann.type)}")

    call_args = "{" + ", ".join(f"{name!r}: {name}" for name in params) + "}"
    model = create_model(
        name, **params, __config__=ConfigDict(extra="forbid", validate_by_name=True)
    )
    namespace: dict[str, Any] = {"__model": model, "Unset": Unset}
    code = "\n".join(
        [
            f"def endpoint({', '.join(func_args)}) -> {returns}:",
            f"    _callargs = {{ _k: _v for _k, _v in {call_args}.items() if _v is not Unset }}",
            f"    return __model(**_callargs).model_dump(mode='json', exclude_unset=True, by_alias=True)",
        ]
    )
    exec(code, namespace)
    endpoint = namespace["endpoint"]
    endpoint.__name__ = name.rsplit(".", 1)[1] if "." in name else name
    endpoint.__qualname__ = name
    endpoint.__module__ = parent_namespace["__name__"]

    @wraps(endpoint)
    def func(api: VulnersApiBase, *args: Any, **kwargs: Any) -> Any:
        params = endpoint(*args, **kwargs)
        response = api._send_request(method, url, params, path_params, add_api_key)
        content = api._handle_response(response)
        if response_handler:
            content = response_handler(content)
        if wrapper is not None:
            content = wrapper(api, content)
        return content

    func.__doc__ = description
    return func


class ResultSet(list):
    total = None

    @classmethod
    def from_dataset(cls, data, total):
        ret = cls(data)
        ret.total = total
        return ret


class _Unset:
    def __repr__(self) -> str:
        return "Unset"


Unset = _Unset()
