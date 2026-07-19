"""VScannerApi object-model tests."""

from __future__ import annotations

import base64
import uuid
from typing import get_type_hints

import pytest

import vulners
from vulners.vscanner import Project, ProjectList, ResultList, Task, TaskList


@pytest.fixture
def vapi(make_api):
    return make_api(vulners.VScannerApi)


class TestAnnotations:
    """The object model annotates vscanner id fields as uuid.UUID.

    The list wrappers are parametrized over their element type. (ApiObject
    stores the raw JSON body verbatim, so the values are the strings the server
    sends at runtime; the UUID annotation documents the identifier type.)
    """

    def test_list_wrappers_subclass_plain_list(self):
        # The string forward-ref base still resolves to plain list at runtime.
        assert ProjectList.__bases__ == (list,)
        assert TaskList.__bases__ == (list,)
        assert ResultList.__bases__ == (list,)

    def test_id_fields_annotated_uuid(self):
        assert get_type_hints(Project)["_id"] is uuid.UUID
        task_hints = get_type_hints(Task)
        assert task_hints["_id"] is uuid.UUID
        assert task_hints["project_id"] is uuid.UUID
        assert task_hints["context_id"] is uuid.UUID

    def test_delegate_return_annotations_resolve(self):
        assert get_type_hints(Project.get_tasks)["return"] is TaskList
        assert get_type_hints(Project.create_task)["return"] is Task
        assert get_type_hints(Project.get_results)["return"] is ResultList

    def test_projects_roundtrip_ids_are_str(self, vapi, server):
        server.enqueue_envelope(
            [
                {
                    "_id": "00000000-0000-4000-8000-000000000001",
                    "name": "synthetic-project",
                    "license_id": "00000000-0000-4000-8000-0000000000aa",
                    "notification": {"period": "disabled", "email": [], "slack": []},
                    "result_expire_in": None,
                }
            ]
        )
        projects = vapi.get_projects()
        assert isinstance(projects, ProjectList)
        assert isinstance(projects[0], Project)
        # runtime value is a str, and the Mapping interface still works
        assert isinstance(projects[0]._id, str)
        assert projects[0]["name"] == "synthetic-project"
        assert dict(projects[0])["license_id"] == "00000000-0000-4000-8000-0000000000aa"

    def test_tasks_roundtrip_project_id_is_str(self, vapi, server):
        pid = "00000000-0000-4000-8000-000000000001"
        server.enqueue_envelope(
            [
                {
                    "_id": "00000000-0000-4000-8000-000000000002",
                    "name": "synthetic-task",
                    "project_id": pid,
                    "networks": ["10.0.0.0/24"],
                    "ports": ["443"],
                    "timing": "T3",
                    "schedule": "",
                    "enabled": True,
                    "context_id": "00000000-0000-4000-8000-000000000003",
                }
            ]
        )
        tasks = vapi.get_tasks(pid)
        assert isinstance(tasks, TaskList)
        assert isinstance(tasks[0], Task)
        assert isinstance(tasks[0].project_id, str)
        assert tasks[0].project_id == pid


class TestImageUriValidation:
    """get_image_binary must not let a server image_uri retarget the request.

    A "../" or a path escaping /vscanner/screen/ raises ValueError before any
    request; legitimate values are sent unchanged.
    """

    def test_happy_path(self, vapi, server):
        server.enqueue_raw(b"PNGDATA", "image/png")
        out = vapi.get_image_binary("443.png")
        assert out == b"PNGDATA"
        assert server.last.url.path == "/vscanner/screen/443.png"

    def test_nested_path_allowed(self, vapi, server):
        server.enqueue_raw(b"PNGDATA", "image/png")
        vapi.get_image_binary("res/1/443.png")
        assert server.last.url.path == "/vscanner/screen/res/1/443.png"

    def test_inner_dotdot_that_stays_in_bounds_allowed(self, vapi, server):
        server.enqueue_raw(b"PNGDATA", "image/png")
        vapi.get_image_binary("a/../b.png")
        # normalizes to /vscanner/screen/b.png, still under the prefix
        assert len(server.requests) == 1

    def test_traversal_rejected_without_request(self, vapi, server):
        with pytest.raises(ValueError):
            vapi.get_image_binary("../../api/v3/apiKey/info")
        assert server.requests == []

    def test_empty_uri_rejected_without_request(self, vapi, server):
        with pytest.raises(ValueError):
            vapi.get_image_binary("")
        assert server.requests == []

    def test_encoded_traversal_rejected_without_request(self, vapi, server):
        # a percent-encoded separator must not smuggle a traversal past the
        # guard: normpath treats "%2f" as an ordinary char, so the uri is
        # decoded before normalizing
        with pytest.raises(ValueError):
            vapi.get_image_binary("..%2f..%2fapi%2fv3%2fapiKey%2finfo")
        assert server.requests == []

    def test_double_encoded_traversal_rejected_without_request(self, vapi, server):
        with pytest.raises(ValueError):
            vapi.get_image_binary("..%252f..%252fapi%252fv3%252fapiKey%252finfo")
        assert server.requests == []

    def test_backslash_traversal_rejected_without_request(self, vapi, server):
        # posixpath.normpath does not treat "\" as a separator, so a backslash
        # traversal must be folded to "/" before the prefix check
        with pytest.raises(ValueError):
            vapi.get_image_binary("..\\..\\api\\v3\\apiKey\\info")
        assert server.requests == []

    def test_encoded_backslash_traversal_rejected_without_request(self, vapi, server):
        with pytest.raises(ValueError):
            vapi.get_image_binary("..%5c..%5capi%5cv3%5capiKey%5cinfo")
        assert server.requests == []

    def test_legit_percent_encoded_char_sent_unchanged(self, vapi, server):
        # a legitimate encoded char (space) stays under the prefix once decoded
        # and the wire still carries the original encoding byte-for-byte
        server.enqueue_raw(b"PNGDATA", "image/png")
        out = vapi.get_image_binary("foo%20bar.png")
        assert out == b"PNGDATA"
        assert server.last.url.raw_path == b"/vscanner/screen/foo%20bar.png"

    def test_excessive_percent_encoding_rejected_without_request(self, vapi, server):
        # A server uri with deeply nested percent-encoding must be rejected
        # rather than driving the decode loop into quadratic work; no request.
        nested = "%" + "25" * 60 + "41.png"
        with pytest.raises(ValueError):
            vapi.get_image_binary(nested)
        assert server.requests == []

    def test_as_base64(self, vapi, server):
        server.enqueue_raw(b"PNGDATA", "image/png")
        out = vapi.get_image_binary("443.png", as_base64=True)
        assert out == base64.b64encode(b"PNGDATA")

    def test_get_screenshot_missing_returns_none(self, vapi, server):
        from vulners.vscanner import Result

        result = Result(vapi, {"screens": {}})
        assert result.get_screenshot(443) is None
        assert server.requests == []
