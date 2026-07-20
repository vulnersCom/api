"""Pins for the endpoint() code generation machinery.

Covers: generated signatures, Unset filtration, declared defaults always reaching
the wire (wire-contract pin, protects against this class of edits), pydantic
aliases and extra=forbid -> TypeError for unknown kwargs.
"""

from __future__ import annotations

import inspect
import pathlib
import typing
from typing import Annotated

import orjson
import pytest
from annotated_types import Gt
from pydantic import Field

import vulners.base
from vulners.base import VulnersApiProxy, endpoint
from vulners.vulners.audit import AuditApi
from vulners.vulners.search import SearchApi


def _iter_endpoint_functions():
    """Yield (owner_class, attr_name, func) for every endpoint()-generated method
    across the shipped package.

    Endpoints are identified by a ``__wrapped__`` target whose code lives in
    exec-generated code (``co_filename`` is not a real file on disk), which keeps
    the discriminator stable across the filename change and excludes the
    @deprecated proxy shims (their wrapped body is real source).
    """
    import importlib
    import os
    import pkgutil
    import types

    import vulners

    seen: set = set()
    for info in pkgutil.walk_packages(
        vulners.__path__, vulners.__name__ + ".", onerror=lambda name: None
    ):
        try:
            module = importlib.import_module(info.name)
        except Exception:
            continue
        for cls in vars(module).values():
            if not isinstance(cls, type):
                continue
            for attr_name, attr in vars(cls).items():
                if not isinstance(attr, types.FunctionType):
                    continue
                wrapped = getattr(attr, "__wrapped__", None)
                if wrapped is None or os.path.exists(wrapped.__code__.co_filename):
                    continue
                key = (cls.__module__, cls.__qualname__, attr_name)
                if key not in seen:
                    seen.add(key)
                    yield cls, attr_name, attr


class TestSignatures:
    def test_unbound_endpoint_signature_leads_with_self(self):
        # pin: unbound endpoint reads (self, <wire params>)
        sig = inspect.signature(SearchApi.get_bulletin_history)
        assert list(sig.parameters) == ["self", "id"]

    def test_unbound_signature_defaults(self):
        sig = inspect.signature(AuditApi.software)
        assert list(sig.parameters) == [
            "self",
            "software",
            "match",
            "fields",
            "config",
            "catalog",
        ]
        assert sig.parameters["software"].default is inspect.Parameter.empty
        assert sig.parameters["match"].default == "partial"
        assert sig.parameters["catalog"].default == "official"
        assert sig.parameters["fields"].default is vulners.base.Unset
        assert sig.parameters["config"].default is vulners.base.Unset

    def test_bound_single_param_endpoint_keeps_its_param(self, api):
        # bound endpoint methods keep their first wire parameter
        sig = inspect.signature(api.search.get_bulletin_history)
        assert list(sig.parameters) == ["id"]

    def test_bound_multi_param_endpoint_keeps_first(self, api):
        # the first wire parameter is no longer swallowed as `self`
        sig = inspect.signature(api.audit.software)
        assert list(sig.parameters) == ["software", "match", "fields", "config", "catalog"]
        # bind agrees with the runtime (self is dropped for the bound method)
        bound = sig.bind(["synthetic-product 1.0"])
        assert bound.arguments["software"] == ["synthetic-product 1.0"]

    def test_bound_zero_param_endpoint_introspects_as_empty(self, api):
        # a zero-wire-param endpoint introspects as an empty signature
        sig = inspect.signature(api.archive.getsploit)
        assert list(sig.parameters) == []

    def test_getfullargspec_reflects_leading_self(self):
        # getfullargspec follows the same __signature__ now (honest contract)
        spec = inspect.getfullargspec(AuditApi.software)
        assert spec.args[0] == "self"
        assert "software" in spec.args

    def test_every_endpoint_unbound_signature_leads_with_self(self):
        # full sweep of the shipped endpoint surface: no bound method may drop a
        # real wire parameter, so every unbound generated function must lead with
        # self
        funcs = list(_iter_endpoint_functions())
        assert len(funcs) > 30  # sanity: ~50 generated endpoints ship
        for cls, name, attr in funcs:
            params = list(inspect.signature(attr).parameters)
            assert params and params[0] == "self", (cls.__qualname__, name, params)


class TestWireGeneration:
    def test_unset_defaults_are_not_sent(self, api, server):
        server.enqueue_json({"result": []})
        api.audit.software(software=["synthetic-product 1.0"])
        body = orjson.loads(server.last.content)
        assert "fields" not in body
        assert "config" not in body

    def test_declared_defaults_always_go_on_wire(self, api, server):
        # wire-contract pin: match="partial", catalog="official" are ALWAYS
        # serialized even when the caller does not pass them
        server.enqueue_json({"result": []})
        api.audit.software(software=["synthetic-product 1.0"])
        body = orjson.loads(server.last.content)
        assert body == {
            "software": ["synthetic-product 1.0"],
            "match": "partial",
            "catalog": "official",
        }

    def test_field_alias_used_on_wire(self, api, server):
        server.enqueue_json({"result": {}})
        api.audit.linux_audit(
            os_name="syntheticos", os_version="99", packages=["synthetic-pkg-1.0.0.noarch"]
        )
        body = orjson.loads(server.last.content)
        assert body == {
            "osName": "syntheticos",
            "osVersion": "99",
            "packages": ["synthetic-pkg-1.0.0.noarch"],
            "osArch": None,
            "includeUnofficial": False,
            "includeCandidates": False,
            "includeAnyVersion": False,
            "cvelistMetrics": False,
        }

    def test_unknown_kwarg_raises_type_error(self, api, server):
        with pytest.raises(TypeError):
            api.audit.software(software=["synthetic-product 1.0"], bogus_kwarg=1)
        assert server.requests == []

    def test_validation_error_before_any_request(self, api, server):
        with pytest.raises(Exception) as excinfo:
            api.audit.software(software=[])  # min_length=1
        assert excinfo.type.__name__ == "ValidationError"
        assert server.requests == []


class TestAnnotatedMetadata:
    """endpoint() must accept legal Annotated metadata shapes at build time:
    ``Annotated[int, Gt(0)]`` (no FieldInfo) and
    ``Annotated[int, Gt(0), Field(default=1)]`` (FieldInfo not first).
    """

    def test_annotated_constraint_without_fieldinfo_builds_and_enforces(self, api, server):
        class _AnnotatedApi(VulnersApiProxy):
            fetch = endpoint(
                "_AnnotatedApi.fetch",
                method="POST",
                url="/annotated/gt/",
                params={"count": Annotated[int, Gt(0)]},
            )

        proxy = _AnnotatedApi(api)
        # the pydantic constraint is still applied (x=0 rejected before any HTTP)
        with pytest.raises(Exception) as excinfo:
            proxy.fetch(count=0)
        assert excinfo.type.__name__ == "ValidationError"
        assert server.requests == []
        # a valid value goes out unchanged
        server.enqueue_json({"result": []})
        proxy.fetch(count=5)
        assert orjson.loads(server.last.content) == {"count": 5}

    def test_default_taken_from_fieldinfo_not_first_metadata(self, api, server):
        class _AnnotatedDefaultApi(VulnersApiProxy):
            fetch = endpoint(
                "_AnnotatedDefaultApi.fetch",
                method="POST",
                url="/annotated/default/",
                params={"count": Annotated[int, Gt(0), Field(default=1)]},
            )

        # signature default comes from the FieldInfo (1), not from Gt(0)
        sig = inspect.signature(_AnnotatedDefaultApi.fetch)
        assert sig.parameters["count"].default == 1
        # and the default reaches the wire when omitted
        server.enqueue_json({"result": []})
        _AnnotatedDefaultApi(api).fetch()
        assert orjson.loads(server.last.content) == {"count": 1}

    def test_alias_resolved_when_fieldinfo_not_first(self, api, server, tmp_path):
        class _NeutralMarker:
            pass

        upload = tmp_path / "payload.bin"
        upload.write_bytes(b"payload")

        class _AnnotatedAliasApi(VulnersApiProxy):
            send = endpoint(
                "_AnnotatedAliasApi.send",
                method="POST",
                url="/annotated/alias/",
                params={
                    "the_file": Annotated[
                        pathlib.Path, _NeutralMarker(), Field(alias="theFile")
                    ]
                },
            )

        server.enqueue_json({"result": "OK"})
        _AnnotatedAliasApi(api).send(the_file=upload)
        # the file param is uploaded under its FieldInfo alias
        assert b'name="theFile"' in server.last.content

    def test_all_declared_endpoints_import_without_crash(self):
        # the whole shipped surface builds
        import vulners.vulners.audit  # noqa: F401
        import vulners.vulners.search  # noqa: F401
        import vulners.vscanner  # noqa: F401


class TestTypeHints:
    """Generated functions must expose resolvable type hints, so
    get_type_hints() does not raise NameError (sphinx autodoc,
    pydantic.validate_call, beartype and any runtime hint tooling depend on it).
    """

    def test_get_type_hints_resolves_on_every_endpoint(self):
        funcs = list(_iter_endpoint_functions())
        assert len(funcs) > 30
        for cls, name, attr in funcs:
            hints = typing.get_type_hints(attr)  # no NameError
            typing.get_type_hints(attr, include_extras=True)  # sphinx path
            assert "return" in hints, (cls.__qualname__, name)

    def test_annotations_stay_strings(self):
        raw = AuditApi.software.__wrapped__.__annotations__
        assert isinstance(raw["software"], str)
        assert isinstance(raw["match"], str)
        assert isinstance(raw["return"], str)

    def test_endpoint_defined_without_future_import_keeps_string_annotations(self):
        # the generated code is compiled with the annotations future flag set
        # explicitly (dont_inherit=True), so a defining module WITHOUT
        # `from __future__ import annotations` still yields string annotations
        src = (
            "from vulners.base import endpoint\n"
            "ep = endpoint('Mod.ep', method='GET', url='/x/{id}/', params={'id': str})\n"
        )
        namespace = {"__name__": "no_future_mod"}
        exec(compile(src, "<no_future>", "exec", dont_inherit=True), namespace)
        ep = namespace["ep"]
        assert ep.__wrapped__.__annotations__["id"] == "str"
        assert typing.get_type_hints(ep)["id"] is str

    def test_get_type_hints_returns_real_types_not_strings(self):
        hints = typing.get_type_hints(AuditApi.linux_audit)
        # osName alias etc. are wire-only; the resolved hint objects are types,
        # not the raw annotation strings
        assert not any(isinstance(v, str) for v in hints.values())


class TestModuleResolution:
    """endpoint() must not depend on the CPython-only sys._getframe at import.

    The generated function's __module__ resolves to the caller's module, and the
    whole import path survives on an implementation without sys._getframe (both
    the frame guard in endpoint() and pydantic's own create_model frame call).
    """

    def test_default_module_is_caller_module(self):
        from vulners.vscanner import VScannerApi

        assert AuditApi.software.__module__ == "vulners.vulners.audit"
        assert VScannerApi.get_projects.__module__ == "vulners.vscanner"

    def test_missing_name_in_caller_globals_falls_back(self):
        namespace: dict = {}  # deliberately no __name__ key
        exec(
            compile(
                "from vulners.base import endpoint\n"
                "ep = endpoint('Ex.n', method='GET', url='/n/')\n",
                "<no_name>",
                "exec",
            ),
            namespace,
        )
        assert namespace["ep"].__module__ == "vulners.base"

    def test_import_survives_without_getframe(self, monkeypatch):
        monkeypatch.delattr(vulners.base.sys, "_getframe")
        # exercises both the endpoint() frame guard and create_model(__module__=)
        ep = endpoint("Ex.g", method="POST", url="/g/", params={"id": str})
        assert ep.__module__ == "vulners.base"

    def test_extra_positional_argument_raises_type_error(self):
        # endpoint() takes 11 parameters; a stray 12th positional is rejected
        with pytest.raises(TypeError):
            endpoint(
                "Ex.p", "GET", "/p/", None, None, None, True, None, False, None, None, "x"
            )

    def test_full_package_imports_without_getframe_subprocess(self):
        import subprocess
        import sys

        code = (
            "import sys\n"
            "del sys._getframe\n"
            "import vulners\n"
            "from vulners.vulners.audit import AuditApi\n"
            "assert AuditApi.software.__module__ == 'vulners.base', AuditApi.software.__module__\n"
            "print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"
