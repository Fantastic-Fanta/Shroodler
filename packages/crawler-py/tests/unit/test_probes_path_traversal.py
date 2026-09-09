from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.path_traversal import probe_path_traversal


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kw):
        return self.handler(method, url, kw)

    def close(self):
        pass


def test_path_traversal_via_query_param():
    def handler(method, url, kw):
        if "etc/passwd" in url or "etc%2Fpasswd" in url:
            return FakeResp(200, "root:x:0:0:root:/root:/bin/bash")
        return FakeResp(200, "ok")

    findings = probe_path_traversal(
        "http://127.0.0.1/view",
        [{"name": "file"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "path-traversal"
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "exposed-file"


def test_path_traversal_via_path_suffix_without_params():
    def handler(method, url, kw):
        if "etc/passwd" in url or "etc%2Fpasswd" in url:
            return FakeResp(200, "root:*:0:0:System")
        return FakeResp(200, "ok")

    findings = probe_path_traversal(
        "http://127.0.0.1/static",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "path-traversal" for f in findings)


def test_path_traversal_clean_response():
    findings = probe_path_traversal(
        "http://127.0.0.1/view",
        [{"name": "file"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "not found")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_path_traversal_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_path_traversal(
        "http://127.0.0.1/view",
        [{"name": "file"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []


def test_path_traversal_multipart_upload_passwd_body():
    def handler(method, url, kw):
        files = kw.get("files") or {}
        data = kw.get("data") or {}
        if method == "POST" and files:
            uploaded = files.get("uploadedFile") or files.get("file")
            assert uploaded is not None
            filename, content, content_type = uploaded
            assert filename == "../../etc/passwd"
            assert content == b"\xff\xd8\xff"
            assert content_type == "image/jpeg"
            assert data.get("fullName") == "../../etc/passwd"
            return FakeResp(200, "root:x:0:0:root:/root:/bin/bash")
        return FakeResp(200, "ok")

    findings = probe_path_traversal(
        "http://127.0.0.1/PathTraversal/profile-upload",
        [
            {"name": "uploadedFile"},
            {"name": "fullName"},
            {"name": "email"},
            {"name": "password"},
        ],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "path-traversal"
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert "multipart" in (hit.evidence or "")


def test_path_traversal_multipart_uses_alternate_file_param_name():
    def handler(method, url, kw):
        files = kw.get("files") or {}
        if method == "POST" and "avatarFile" in files:
            return FakeResp(200, "error writing ../../etc/passwd")
        return FakeResp(200, "ok")

    findings = probe_path_traversal(
        "http://127.0.0.1/upload",
        [{"name": "avatarFile"}, {"name": "fullName"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "path-traversal" for f in findings)


def test_path_traversal_multipart_filesystem_error_is_confirmed():
    def handler(method, url, kw):
        if method == "POST" and kw.get("files"):
            return FakeResp(
                200,
                '{"lessonCompleted":false,"feedback":"try again",'
                '"output":"No such file or directory"}',
            )
        return FakeResp(200, "ok")

    findings = probe_path_traversal(
        "http://127.0.0.1/PathTraversal/profile-upload",
        [{"name": "uploadedFile"}, {"name": "fullName"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "path-traversal"
    assert hit.confidence == "confirmed"
