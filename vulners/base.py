import os
import stat
import re
import uuid
import requests
import threading
import json
import functools
import inspect
from time import time, sleep
from collections import defaultdict, OrderedDict
from six import string_types, with_metaclass
from requests import adapters, cookies
from urllib3.util.retry import Retry
from appdirs import user_cache_dir
from . import __version__


try:
    _getargspec = inspect.getfullargspec  # noqa
except AttributeError:
    _getargspec = inspect.getargspec  # noqa


class VulnersApiError(Exception):
    def __init__(self, http_status, data):
        super(VulnersApiError, self).__init__(data)
        self.http_status = http_status


class VulnersApiMeta(type):
    def __new__(cls, name, bases, attrs):
        new_type = type.__new__
        if not bases:
            return new_type(cls, name, bases, attrs)
        for key, value in list(attrs.items()):
            if isinstance(value, Endpoint):
                attrs[key] = value.build(key, attrs.get("ratelimit_key"))
        new_class = new_type(cls, name, bases, attrs)
        return new_class


class RateLimitBucket(object):
    """An implementation of the Token Bucket algorithm."""

    def __init__(self, rate=10.0, burst=1.0):
        """Initialise an instance of the RateLimit allowing a default rate of 10 calls
        per 1 seconds when no arguments are supplied.
        :param rate:
            The number of calls per second. Default 10.
        """
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


class PersistentCookieJar(cookies.RequestsCookieJar):

    _cookie_locks = defaultdict(threading.RLock)

    def __init__(self, file_path=None, *args, **kwargs):
        super(PersistentCookieJar, self).__init__(*args, **kwargs)
        self._set_cookie_counter = 0
        if file_path:
            self._file_path = file_path
        else:
            cache_dir = user_cache_dir("Vulners", "Vulners.Inc")
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
            self._file_path = os.path.join(cache_dir, "cookies.txt")
        self._recover()

    def dump(self):
        if self._set_cookie_counter:
            with self._cookie_locks[self._file_path]:
                with open(self._file_path, "wb") as cookie_file:
                    cookie_file.write(
                        json.dumps(self.get_dict(), ensure_ascii=True).encode("ascii")
                    )
            self._set_cookie_counter = 0

    def _recover(self):
        try:
            mode = os.stat(self._file_path).st_mode
        except OSError:
            return
        if not stat.S_ISREG(mode):
            raise OSError("%s is not a regular file" % self._file_path)
        with self._cookie_locks[self._file_path]:
            with open(self._file_path, "rb") as cookie_file:
                try:
                    cookies_dict = json.loads(cookie_file.read())
                except (TypeError, ValueError):
                    return
        if not isinstance(cookies_dict, dict):
            return
            # this method internally calls set_cookie
        self.update(cookies_dict)
        self._set_cookie_counter = 0

    def extract_cookies(self, response, request):
        super(PersistentCookieJar, self).extract_cookies(response, request)
        self.dump()

    def set_cookie(self, *args, **kwargs):
        self._set_cookie_counter += 1
        return super(PersistentCookieJar, self).set_cookie(*args, **kwargs)


class VulnersApiBase(with_metaclass(VulnersApiMeta)):
    # Retry status codes
    retry_codes = (500, 502, 503, 504)
    # How many times to retry
    retry_count = 3

    _ratelimits = defaultdict(RateLimitBucket)

    def __init__(
        self, api_key, proxies=None, persistent=True, server_url="https://vulners.com"
    ):
        """
        Create VScanner API object.

        :param api_key:
            string with Vulners API key. You can obtain one from the https://vulners.com
        :param proxies:
            dict for proxy supporting. Example: {"https": "myproxy.com:3128"}
        """
        if not api_key:
            raise ValueError(
                "API key must be provided. You can obtain one for free at https://vulners.com"
            )

        if not isinstance(api_key, string_types):
            raise TypeError("api_key parameter must be a string value")

        self._sess = self._create_session(proxies, server_url, persistent)
        self._api_key = api_key
        self._server_url = server_url

    def _create_session(self, proxies, server_url, persistent):
        assert proxies is None or isinstance(proxies, dict), "proxies must be a dict"
        session = requests.session()
        retries = Retry(total=self.retry_count, status_forcelist=self.retry_codes)
        adapter = adapters.HTTPAdapter(max_retries=retries)
        session.mount(server_url, adapter)
        session.headers.update(
            {
                "Connection": "Keep-Alive",
                "User-Agent": "Vulners Python API %s" % __version__,
            }
        )
        if persistent:
            session.cookies = PersistentCookieJar()
        if proxies:
            session.proxies.update(proxies)
        return session

    @staticmethod
    def adapt_response(response, method, expected_result):
        if expected_result == "json":
            if response.content:
                result = response.json()
            else:
                result = None
            if response.status_code >= 400:
                raise VulnersApiError(response.status_code, result)
            if isinstance(result, dict) and "data" in result:
                data = result["data"]
                if isinstance(data, dict) and data.get("error"):
                    raise VulnersApiError(response.status_code, data)
                return data
            return result
        elif response.status_code >= 400:
            if response.content:
                result = response.json()
            else:
                result = None
            raise VulnersApiError(response.status_code, result)
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

    def _send_request(
        self,
        method,
        url,
        body_params,
        path_params,
        ratelimit_key=None,
        result_type="json",
    ):
        body_params["apiKey"] = self._api_key
        url = self._server_url + url.format(**path_params)
        kwargs = {"params" if method in ("get", "delete") else "json": body_params}
        bucket = self._ratelimits[ratelimit_key or url]
        bucket.consume()
        response = getattr(self._sess, method)(url, **kwargs)
        self._update_ratelimit(bucket, response)
        result = self.adapt_response(response, method, result_type)
        response.raise_for_status()
        return result, response.headers


_Nothing = object()


class ParamError(ValueError):
    def __init__(self, msg, param):
        self.msg = msg
        self.param = param

    def __str__(self):
        return self.msg % self.param


class Param(object):
    def __init__(self, default=_Nothing, description=None, required=True, param=None):
        if not required:
            if default is _Nothing:
                default = None
        self.param = param
        self.default = default
        self.required = required
        self.description = description


class Const(object):
    def __init__(self, value):
        self.value = value


class String(Param):
    def __init__(self, choices=None, *args, **kwargs):
        super(String, self).__init__(*args, **kwargs)
        self.choices = choices

    def validate(self, param, value):
        if not isinstance(value, string_types):
            raise ParamError("%s expected to be a string", param)
        if self.choices is not None and value not in self.choices:
            raise ParamError(
                "%%s expected to be on of (%s)" % ", ".join(self.choices), param
            )
        return value


class UUID(Param):
    @staticmethod
    def validate(param, value):
        try:
            return str(uuid.UUID(value))
        except (TypeError, ValueError):
            raise ParamError("%s expected to be an uuid", param)


class Dict(Param):
    @staticmethod
    def validate(param, value):
        if not isinstance(value, dict):
            raise ParamError("%s expected to be a dict", param)
        return value


class List(Param):
    def __init__(self, item=None, **kwargs):
        super(List, self).__init__(**kwargs)
        self.item = item

    @staticmethod
    def validate_items(validator, param, value):
        result = []
        for idx, val in enumerate(value):
            try:
                result.append(validator(idx, val))
            except ParamError as e:
                raise ParamError(e.msg, "%s.%s" % (param, e.param))
        return result

    def validate(self, param, value):
        if not isinstance(value, list):
            raise ParamError("%s expected to be a list", param)
        if self.item is not None:
            value = self.validate_items(self.item.validate, param, value)
        return value


class Tuple(List):
    def __init__(self, accept_list=True, **kwargs):
        super(Tuple, self).__init__(**kwargs)
        self.accept_list = accept_list

    def validate(self, param, value):
        if not isinstance(value, (list, tuple) if self.accept_list else tuple):
            raise ParamError("%s expected to be a tuple", param)
        if self.item is not None:
            value = self.validate_items(self.item.validate, param, value)
        return tuple(value)


class Integer(Param):
    def __init__(self, minimum=None, maximum=None, **kwargs):
        super(Integer, self).__init__(**kwargs)
        self.minimum = minimum
        self.maximum = maximum

    def validate(self, param, value):
        if not isinstance(value, int):
            raise ParamError("%s expected to be an int", param)
        if self.minimum is not None and value < self.minimum:
            raise ParamError("%%s must be greater or equal to %d" % self.minimum, param)
        if self.maximum is not None and value > self.maximum:
            raise ParamError("%%s must be less or equal to %d" % self.maximum, param)
        return value


class Float(Param):
    def __init__(self, minimum=None, maximum=None, **kwargs):
        super(Float, self).__init__(**kwargs)
        self.minimum = minimum
        self.maximum = maximum

    def validate(self, param, value):
        if not isinstance(value, float):
            raise TypeError("%s expected to be a float" % param)
        if self.minimum is not None and value < self.minimum:
            raise ParamError("%%s must be greater or equal to %d" % self.minimum, param)
        if self.maximum is not None and value > self.maximum:
            raise ParamError("%%s must be less or equal to %d" % self.maximum, param)
        return value


class Boolean(Param):
    @staticmethod
    def validate(param, value):
        if not isinstance(value, bool):
            raise TypeError("%s expected to be a bool" % param)
        return value


_unset = object()


def validate_params(**params):
    def decorator(func):
        spec = _getargspec(func)
        for param in params:
            if param not in spec.args:
                raise TypeError("No such argument %s" % param)
        spec_defaults = spec.defaults or ()
        default_values = (_unset,) * (
            len(spec.args) - len(spec_defaults)
        ) + spec_defaults
        defaults = {k: v for k, v in zip(spec.args, default_values) if v is not _unset}
        args = ", ".join([arg for arg in spec.args])
        func_args = ", ".join(
            [
                (name if default is _unset else ("%s=%r" % (name, default)))
                for name, default in zip(spec.args, default_values)
            ]
        )
        body = "\n  ".join(
            [
                (
                    ("if {var} is not _D[{var!r}]: " if var in defaults else "")
                    + "{var} = _V[{var!r}].validate({var!r}, {var})"
                ).format(var=var)
                for var in params
            ]
        )
        code = (
            "def {name}({func_args}):\n" "  {body}\n" "  return _func({args})"
        ).format(name=func.__name__, func_args=func_args, body=body, args=args)
        exec_locals = {"_V": params, "_D": defaults, "_func": func}
        exec(code, exec_locals, exec_locals)
        new_func = exec_locals[func.__name__]
        functools.update_wrapper(new_func, func)
        return new_func

    return decorator


class Endpoint(object):
    _mapping = {
        "str": String,
        "uuid": UUID,
        "int": Integer,
        "float": Float,
        "bool": Boolean,
        "dict": Dict,
    }

    def __call__(self, *args, **kwargs):
        raise RuntimeError("Only for typing")

    def __init__(
        self,
        method,
        url,
        description=None,
        params=None,
        result_type="json",
        content_handler=None,
        wrapper=None
    ):
        assert method in ("get", "post", "put", "delete")
        assert isinstance(url, string_types)
        assert description is None or isinstance(description, string_types)
        assert params is None or isinstance(params, list)
        self.path_params = []
        self.params = OrderedDict()
        for param in [item.strip("{}") for item in re.findall("{[^}]*}", url)]:
            if ":" in param:
                param_type, param_name = param.split(":", 1)
            else:
                param_type, param_name = "str", param
            if "|" in param_name:
                param_name, param_description = param_name.split("|", 1)
            else:
                param_description = ""
            url = url.replace("{" + param + "}", "{" + param_name + "}")
            param_obj = self._mapping[param_type](description=param_description)
            self.path_params.append(param_name)
            self.params[param_name] = param_obj
        self.method = method
        self.url = url
        self.description = description
        self.result_type = result_type
        self.content_handler = content_handler
        self.wrapper = wrapper
        if params:
            for k, v in params:
                self.params[k] = v

    def build(self, name, ratelimit_key=None):
        func_args = []
        func_args_with_default = []
        body_params = []
        path_params = []
        func_locals = {
            "_content_handler": self.content_handler,
            "_wrapper": self.wrapper
        }
        func_locals_reverse = {}
        func_doc = [self.description or name, ""]
        for key, param in self.params.items():
            if isinstance(param, Const):
                const_key = "_const%d" % len(func_locals)
                func_locals[const_key] = param.value
                body_params.append(
                    "body_params[{key!r}] = {const}".format(key=key, const=const_key)
                )
                continue
            if param.default is not _Nothing:
                default_key = "_default%d" % len(func_locals)
                func_locals[default_key] = param.default
                func_args_with_default.append("%s=%s" % (key, default_key))
            else:
                func_args.append(key)
            validate_key = "_validate%d" % len(func_locals)
            if param.validate in func_locals_reverse:
                validate_key = func_locals_reverse[param.validate]
            else:
                func_locals[validate_key] = param.validate
                func_locals_reverse[param.validate] = validate_key
            if key in self.path_params:
                path_params.append(
                    "{key!r}: {validator}({key!r}, {key})".format(
                        key=key, validator=validate_key
                    )
                )
            else:
                param_name = param.param or key
                if param.required:
                    body_params.append(
                        (
                            "body_params[{param_name!r}] = {validator}({key!r}, {key})"
                        ).format(param_name=param_name, key=key, validator=validate_key)
                    )
                else:
                    body_params.append(
                        (
                            "if {key} is not None: "
                            "body_params[{param_name!r}] = {validator}({key!r}, {key})"
                        ).format(param_name=param_name, key=key, validator=validate_key)
                    )
            if param.description:
                func_doc.append("%s: %s" % (key, param.description or ""))
        func_args += func_args_with_default
        code = (
            "def {name}(self, {func_args}):\n"
            "  '''{func_doc}'''\n"
            "  body_params = {{}}\n"
            "  {body_params}\n"
            "  path_params = {{{path_params}}}\n" 
            "  r = self._send_request({method!r}, {url!r}, body_params, path_params, {ratelimit_key!r}, {result!r})\n"
        ).format(
            name=name,
            func_args=", ".join(func_args),
            func_doc="\n".join(func_doc),
            method=self.method,
            url=self.url,
            body_params="\n  ".join(body_params),
            path_params=", ".join(path_params),
            ratelimit_key=ratelimit_key,
            result=self.result_type,
        )
        if self.content_handler:
            code += "  r = _content_handler(*r)\n"
        else:
            code += "  r = r[0]\n"
        if self.wrapper:
            code += "  r = _wrapper(self, r)\n"
        code += "  return r"
        exec(code, func_locals, func_locals)
        return func_locals[name]


class ResultSet(list):
    total = None

    @classmethod
    def from_dataset(cls, data, total):
        ret = cls(data)
        ret.total = total
        return ret
