from __future__ import annotations

import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

PACKAGES = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PACKAGES / "payload-tester"))
sys.path.insert(0, str(PACKAGES / "target-apps" / "app5-injectable"))

from app import app as flask_app  # noqa: E402
from tester import _local, run  # noqa: E402


@pytest.fixture
def origin():
    httpd = make_server("127.0.0.1", 0, flask_app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_refuses_external():
    with pytest.raises(ValueError):
        run({"target": "https://example.com/", "pages": []})


def test_local_helper():
    assert _local("http://127.0.0.1:8087/")
    assert not _local("https://httpbin.org/")


def test_sql_payload_against_app5(origin):
    doc = {
        "target": origin + "/",
        "pages": [
            {
                "url": origin + "/",
                "forms": [
                    {
                        "action": "/search",
                        "method": "POST",
                        "fields": [{"name": "q"}],
                    }
                ],
            }
        ],
    }
    out = run(doc)
    ids = {f["id"] for f in out["findings"]}
    assert "payload-sql-error" in ids
