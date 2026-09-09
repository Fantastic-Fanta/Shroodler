from __future__ import annotations

from shroodler.content_discovery import (
    WORDLIST,
    classify_admin_interface,
    classify_config_file,
    classify_path,
    discover_content,
    is_spa_shell,
)
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
    assert len(findings) == 1
    hit = findings[0]
    assert hit.id == "admin-login-page-found"
    assert hit.severity == "info"
    assert hit.description == "Admin login page reachable at http://127.0.0.1/admin/"
    assert hit.confidence == "confirmed"


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


_SPA_SHELL = (
    "<!doctype html><html><head><title>App</title></head>"
    '<body><div id="root"></div><script src="/static/app.js"></script></body></html>'
)


def test_spa_shell_drops_config_file_exposed():
    assert is_spa_shell(_SPA_SHELL)
    finding = classify_config_file(
        _SPA_SHELL,
        "http://127.0.0.1/config.json",
        "text/html",
        path="/config.json",
    )
    assert finding is None
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient(
            {
                "/config.json": FakeResp(
                    200, _SPA_SHELL, headers={"Content-Type": "text/html"}
                )
            }
        ),
        pacer=Pacer(0),
        paths=("/config.json",),
    )
    assert all(f.id != "config-file-exposed" for f in findings)


def test_env_key_value_config_stays_high():
    body = "DATABASE_URL=postgres://user:hunter2@db/app\nSECRET_KEY=abcdefghijklmnop\n"
    finding = classify_config_file(
        body, "http://127.0.0.1/.env", "text/plain", path="/.env"
    )
    assert finding is not None
    assert finding.id == "config-file-exposed"
    assert finding.severity == "high"
    assert finding.confidence == "confirmed"
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/config.yml": FakeResp(200, body)}),
        pacer=Pacer(0),
        paths=("/config.yml",),
    )
    hit = next(f for f in findings if f.id == "config-file-exposed")
    assert hit.severity == "high"


def test_config_php_html_catch_all_dropped():
    html = "<html><head></head><body><h1>Not Found</h1><p>SPA router</p></body></html>"
    finding = classify_path(
        "/config.php",
        html,
        "http://127.0.0.1/config.php",
        content_type="text/html",
    )
    assert finding is None
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient(
            {
                "/config.php": FakeResp(
                    200, html, headers={"Content-Type": "text/html; charset=utf-8"}
                )
            }
        ),
        pacer=Pacer(0),
        paths=("/config.php",),
    )
    assert findings == []


def test_config_empty_body_downgraded_empty_response():
    finding = classify_config_file("tiny", "http://127.0.0.1/config.json", path="/config.json")
    assert finding is not None
    assert finding.id == "config-file-exposed"
    assert finding.severity == "info"
    assert finding.confidence == "heuristic"
    assert (finding.evidence or "").startswith("[empty-response]")


def test_high_signal_config_without_patterns_is_heuristic():
    finding = classify_config_file(
        "this is a leftover backup dump without structured secrets\n" + ("n" * 40),
        "http://127.0.0.1/backup.sql",
        "text/plain",
        path="/backup.sql",
    )
    assert finding is not None
    assert finding.id == "config-file-exposed"
    assert finding.severity == "medium"
    assert finding.confidence == "heuristic"


def test_sensitive_config_body_still_emits_high():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA0Z3examplekeymaterialhere\n"
    finding = classify_path(
        "/.aws/credentials",
        body,
        "http://127.0.0.1/.aws/credentials",
        content_type="text/plain",
    )
    assert finding is not None
    assert finding.id == "config-file-exposed"
    assert finding.severity == "high"


def test_admin_login_form_downgraded_to_info():
    body = (
        "<html><title>Admin</title><form action='/login'>"
        '<input type="password" name="password">'
        "</form></html>"
        + ("x" * 40)
    )
    finding = classify_admin_interface(body, "http://127.0.0.1/admin/", path="/admin/")
    assert finding is not None
    assert finding.id == "admin-login-page-found"
    assert finding.severity == "info"
    assert finding.description == "Admin login page reachable at http://127.0.0.1/admin/"
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/admin/": FakeResp(200, body)}),
        pacer=Pacer(0),
        paths=("/admin/",),
    )
    hit = findings[0]
    assert hit.id == "admin-login-page-found"
    assert hit.severity == "info"
    assert hit.category == "scan-note"


def test_admin_without_login_wall_kept_medium():
    body = "<html><title>Admin Dashboard</title><table><tr><td>users</td></tr></table></html>"
    findings = discover_content(
        "http://127.0.0.1/",
        client=FakeClient({"/admin/": FakeResp(200, body + ("x" * 40))}),
        pacer=Pacer(0),
        paths=("/admin/",),
    )
    hit = findings[0]
    assert hit.id == "admin-interface-exposed"
    assert hit.severity == "medium"


def test_admin_spa_shell_dropped():
    finding = classify_admin_interface(
        _SPA_SHELL, "http://127.0.0.1/admin/", path="/admin/"
    )
    assert finding is None


def test_admin_plain_html_without_admin_content_dropped():
    body = "<html><body><p>Welcome to the site</p></body></html>" + ("x" * 40)
    finding = classify_path("/admin/", body, "http://127.0.0.1/admin/")
    assert finding is None
