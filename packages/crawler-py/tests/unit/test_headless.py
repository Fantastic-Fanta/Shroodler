from __future__ import annotations

import json

from shroodler.crawler import crawl_url


def test_headless_json_login_injects_auth_cookies(fx, tmp_path):
    """JSON-POST recipe (content_type=json) must authenticate the Playwright
    browser context via the visual login form at /login (WAF-safe path)."""
    # Fixture: /login serves an HTML form; POST to /do-login sets the cookie.
    fx.html(
        "/login",
        '<form method="POST" action="/do-login">'
        '<input name="Username" type="text">'
        '<input name="Password" type="password">'
        '<button type="submit">Login</button></form>',
    )

    def do_login(req):
        return 302, {"Location": "/", "Set-Cookie": "session=auth-ok; Path=/"}, b""

    fx.on("POST", "/do-login", do_login)
    fx.html("/", '<a href="/protected">enter</a>')
    fx.on(
        "GET",
        "/protected",
        lambda req: (
            (200, {}, b"<p>welcome</p>")
            if "session=" in req.headers.get("Cookie", "")
            else (401, {}, b"<p>not auth</p>")
        ),
    )

    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "url": fx.origin + "/api/login",  # API URL (origin extracted from it)
                "method": "POST",
                "fields": {"Username": "test@example.com", "Password": "secret"},
                "content_type": "json",
                "include_hidden": False,
            }
        ),
        encoding="utf-8",
    )

    result = crawl_url(
        fx.origin + "/",
        depth=2,
        ignore_robots=True,
        mode="headless",
        login_recipe=str(recipe),
    )
    protected = [p for p in result.pages if "/protected" in p.url]
    assert protected, "protected page was never reached"
    # If the session cookie was injected, the server returns 200; otherwise 401.
    assert all(p.status_code == 200 for p in protected), (
        "headless browser did not carry session cookie to /protected — got "
        + str([p.status_code for p in protected])
    )


def test_headless_sees_js_injected_form(fx):
    fx.html(
        "/",
        """
        <div id="root"></div>
        <script>
          const f = document.createElement('form');
          f.action = '/injected';
          f.method = 'POST';
          const i = document.createElement('input');
          i.name = 'token';
          f.appendChild(i);
          document.getElementById('root').appendChild(f);
        </script>
        """,
    )
    result = crawl_url(fx.origin + "/", mode="headless", depth=0)
    names = {field.name for p in result.pages for form in p.forms for field in form.fields}
    assert "token" in names
