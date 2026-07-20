"""Field-enum widening tests.

The bulletin/audit field enums gained server-confirmed values and a ``| str``
union so a legal server field name no longer trips a client-side
ValidationError, while known values stay byte-identical on the wire.
"""

from __future__ import annotations

import orjson
import pytest


def _software():
    return [{"product": "nginx", "version": "1.0"}]


class TestAuditFields:
    def test_repro_extra_fields_no_longer_rejected(self, api, server):
        # server-confirmed extra field names are accepted
        server.enqueue_envelope({"result": {"ok": True}})
        api.audit.software(software=_software(), fields=["cvss3", "exploits"])
        body = orjson.loads(server.last.content)
        assert body["fields"] == ["cvss3", "exploits"]

    def test_new_enum_values_accepted(self, api, server):
        server.enqueue_envelope({"result": {"ok": True}})
        api.audit.software(software=_software(), fields=["cvss", "bulletinFamily", "lastseen"])
        body = orjson.loads(server.last.content)
        assert body["fields"] == ["cvss", "bulletinFamily", "lastseen"]

    def test_known_values_byte_identical(self, api, server):
        server.enqueue_envelope({"result": {"ok": True}})
        api.audit.software(software=_software(), fields=["title", "cvss"])
        body = orjson.loads(server.last.content)
        assert body["fields"] == ["title", "cvss"]
        # defaults still ride along unchanged
        assert body["match"] == "partial"
        assert body["catalog"] == "official"

    def test_omitted_fields_not_serialized(self, api, server):
        server.enqueue_envelope({"result": {"ok": True}})
        api.audit.software(software=_software())
        body = orjson.loads(server.last.content)
        assert "fields" not in body

    def test_host_fields_passthrough(self, api, server):
        server.enqueue_envelope({"result": {"ok": True}})
        api.audit.host(software=_software(), fields=["someFutureField"])
        body = orjson.loads(server.last.content)
        assert body["fields"] == ["someFutureField"]

    def test_non_string_field_still_rejected(self, api, server):
        with pytest.raises(Exception) as excinfo:
            api.audit.software(software=_software(), fields=[42])
        assert excinfo.type.__name__ == "ValidationError"
        assert server.requests == []


class TestBulletinFields:
    def test_create_bulletin_fields_passthrough(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0001"}})
        api.subscription_v4.create(
            name="synthetic",
            query={},
            delivery={},
            bulletin_fields=["cvss", "myFutureField"],
        )
        body = orjson.loads(server.last.content)
        assert body["bulletin_fields"] == ["cvss", "myFutureField"]

    def test_update_bulletin_fields_passthrough(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0001"}})
        api.subscription_v4.update(
            id="SYNTHETIC00-SUB-0001",
            name="synthetic",
            query={},
            delivery={},
            bulletin_fields=["bulletinFamily", "lastseen"],
        )
        body = orjson.loads(server.last.content)
        assert body["bulletin_fields"] == ["bulletinFamily", "lastseen"]

    def test_create_default_bulletin_fields_unchanged(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0001"}})
        api.subscription_v4.create(name="synthetic", query={}, delivery={})
        body = orjson.loads(server.last.content)
        assert body["bulletin_fields"] == [
            "title",
            "short_description",
            "type",
            "href",
            "published",
            "modified",
            "ai_score",
        ]
