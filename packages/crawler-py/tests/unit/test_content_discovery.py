from __future__ import annotations

from shroodler.content_discovery import WORDLIST, discover_content
from shroodler.pacer import Pacer


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


class FakeClient:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for suffix, resp in self.mapping.items():
            if url.endswith(suffix) or url.rstrip("/").endswith(suffix.rstrip("/")):
                return resp
        return FakeResp(404, "missing")

    def close(self):
        pass


def test_wordlist_has_about_sixty_paths():
    assert 50 <= len(WORDLIST) <= 90
    assert "/.git/HEAD" in WORDLIST
    assert "/.env" in WORDLIST


def test_git_repo_exposed():
    client = FakeClient(
        {
            "/.git/HEAD": FakeResp(200, "ref: refs/heads/main\n"),
            "/.git/config": FakeResp(200, "[core]\nbare = false\n" + ("x" * 40)),
        }
    )
    findings = discover_content(
        "http://127.0.0.1/",
        client=client,
        pacer=Pacer(0),
        paths=("/.git/HEAD", "/.git/config"),
    )
    hit = next(f for f in findings if f.id == "git-repo-exposed")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "exposed-file"


def test_env_file_exposed():
    body = "DATABASE_URL=postgres://x\nSECRET_KEY=abc\n" + ("n" * 40)
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/.env": FakeResp(200, body)}),
        pacer=Pacer(0),
        paths=("/.env",),
    )
    hit = findings[0]
    assert hit.id == "env-file-exposed"
    assert hit.severity == "critical"


def test_log_file_exposed():
    body = "2026-01-01 00:00:00 ERROR traceback (most recent call last)\n" + ("x" * 40)
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/error.log": FakeResp(200, body)}),
        pacer=Pacer(0),
        paths=("/error.log",),
    )
    hit = findings[0]
    assert hit.id == "log-file-exposed"
    assert hit.severity == "medium"


def test_admin_interface_exposed():
    body = "<html><title>Admin Dashboard</title>" + ("x" * 40) + "</html>"
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/admin/": FakeResp(200, body)}),
        pacer=Pacer(0),
        paths=("/admin/",),
    )
    hit = findings[0]
    assert hit.id == "admin-interface-exposed"
    assert hit.severity == "medium"


def test_admin_login_redirect_is_ignored():
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient(
            {
                "/admin/": FakeResp(
                    302, "moved", headers={"Location": "http://127.0.0.1/login"}
                )
            }
        ),
        pacer=Pacer(0),
        paths=("/admin/",),
    )
    assert findings == []


def test_content_discovery_uses_pacer_not_sleep(monkeypatch):
    slept = []
    pacer = Pacer(0, sleeper=lambda s: slept.append(s))
    discover_content(
        "http://127.0.0.1/",
        client=FakeClient({}),
        pacer=pacer,
        paths=("/.env", "/admin/"),
    )
    assert slept == []
