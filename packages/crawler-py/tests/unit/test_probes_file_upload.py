from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.file_upload import probe_file_upload


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=0.0)
        self.headers = headers or {}


class StoreClient:
    """Simulates an app that stores an upload and serves it back."""

    def __init__(self, *, serve_ctype="image/svg+xml", return_url=True, accept=True):
        self.store: dict[str, bytes] = {}
        self.serve_ctype = serve_ctype
        self.return_url = return_url
        self.accept = accept

    def request(self, method, url, **kw):
        files = kw.get("files")
        if method.upper() in ("POST", "PUT") and files:
            (filename, content, _ctype) = next(iter(files.values()))
            if not self.accept:
                return FakeResp(400, "rejected")
            path = f"/uploads/{filename}"
            self.store[path] = content if isinstance(content, bytes) else content.encode()
            body = f'{{"ok": true, "url": "{path}"}}' if self.return_url else '{"ok": true}'
            return FakeResp(200, body, {"Content-Type": "application/json"})
        # GET of a stored file.
        for path, content in self.store.items():
            if url.endswith(path):
                return FakeResp(200, content.decode(), {"Content-Type": self.serve_ctype})
        return FakeResp(404, "not found")

    def close(self):
        pass


_FILE_PARAMS = [{"name": "avatar", "in": "file"}]


def test_confirmed_stored_xss_when_served_as_svg():
    client = StoreClient(serve_ctype="image/svg+xml")
    findings = probe_file_upload(
        "http://t/upload", "POST", _FILE_PARAMS, "", client=client, pacer=Pacer(0)
    )
    hit = next(f for f in findings if f.id == "upload-stored-xss")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"


def test_served_as_text_plain_is_not_confirmed():
    # Stored but served as text/plain -> not executable -> only the heuristic lead.
    client = StoreClient(serve_ctype="text/plain")
    findings = probe_file_upload(
        "http://t/upload", "POST", _FILE_PARAMS, "", client=client, pacer=Pacer(0)
    )
    assert not any(f.id == "upload-stored-xss" for f in findings)
    assert any(f.id == "upload-unrestricted-type" for f in findings)


def test_accepted_but_no_url_is_heuristic():
    client = StoreClient(return_url=False)
    findings = probe_file_upload(
        "http://t/upload", "POST", _FILE_PARAMS, "", client=client, pacer=Pacer(0)
    )
    hit = next(f for f in findings if f.id == "upload-unrestricted-type")
    assert hit.severity == "medium"
    assert hit.confidence == "heuristic"


def test_rejected_upload_is_no_finding():
    client = StoreClient(accept=False)
    findings = probe_file_upload(
        "http://t/upload", "POST", _FILE_PARAMS, "", client=client, pacer=Pacer(0)
    )
    assert findings == []


def test_no_file_param_skips():
    client = StoreClient()
    findings = probe_file_upload(
        "http://t/upload", "POST", [{"name": "q", "value": "x"}], "", client=client, pacer=Pacer(0)
    )
    assert findings == []


def test_get_method_skips():
    client = StoreClient()
    findings = probe_file_upload(
        "http://t/upload", "GET", _FILE_PARAMS, "", client=client, pacer=Pacer(0)
    )
    assert findings == []
