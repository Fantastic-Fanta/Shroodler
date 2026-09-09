from __future__ import annotations

import json
from urllib.parse import urlparse

from shroodler.crawler import crawl_url
from shroodler.program import ProgramState, merge_crawl_doc

_START = """
<html><body>
<nav id="menu">
  <a href="#SqlInjection">SQL Injection</a>
  <a href="#XSS">XSS</a>
</nav>
<div id="lesson"></div>
<script>
function load() {
  const id = (location.hash || '').replace(/^#/, '');
  const root = document.getElementById('lesson');
  if (id === 'SqlInjection') {
    root.innerHTML = '<form method="POST" action="/WebGoat/SqlInjection/attack2">'
      + '<input name="username"><input name="password"></form>';
    fetch('/WebGoat/SqlInjection/lesson?from=menu');
    fetch('/WebGoat/SqlInjection/attack2', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'username=guest&password=guest'
    });
  }
  if (id === 'XSS') {
    root.innerHTML = '<form method="POST" action="/WebGoat/CrossSiteScripting/stored">'
      + '<input name="comment"></form>';
  }
}
window.addEventListener('hashchange', load);
if (location.hash) load();
</script>
</body></html>
"""


def test_headless_webgoat_lesson_walk_captures_xhr(fx):
    fx.html("/WebGoat/start.mvc", _START)
    fx.on(
        "GET",
        "/WebGoat/service/lessonmenu.mvc",
        lambda req: (
            200,
            {"Content-Type": "application/json"},
            json.dumps(
                [
                    {
                        "name": "A1",
                        "children": [
                            {"name": "SQL Injection", "link": "SqlInjection"},
                            {"name": "XSS", "link": "XSS"},
                        ],
                    }
                ]
            ).encode("utf-8"),
        ),
    )
    fx.on(
        "GET",
        "/WebGoat/SqlInjection/lesson",
        lambda req: (200, {"Content-Type": "application/json"}, b'{"ok":true}'),
    )
    fx.on(
        "POST",
        "/WebGoat/SqlInjection/attack2",
        lambda req: (200, {"Content-Type": "text/plain"}, b"ok"),
    )

    result = crawl_url(
        fx.origin + "/WebGoat/start.mvc",
        mode="headless",
        depth=1,
        ignore_robots=True,
        max_pages=20,
        no_sitemap=True,
    )
    xhr = {(e.method, urlparse(e.url).path) for e in result.xhr_endpoints}
    assert ("POST", "/WebGoat/SqlInjection/attack2") in xhr
    assert ("GET", "/WebGoat/SqlInjection/lesson") in xhr

    attack = next(
        e
        for e in result.xhr_endpoints
        if urlparse(e.url).path == "/WebGoat/SqlInjection/attack2"
    )
    names = {p["name"] for p in attack.params}
    assert "username" in names
    assert "password" in names

    state = ProgramState(slug="webgoat")
    merge_crawl_doc(state, result.to_dict())
    attack_url = fx.origin + "/WebGoat/SqlInjection/attack2"
    assert attack_url in state.endpoints
    assert state.endpoints[attack_url]["method"] == "POST"
    stored = fx.origin + "/WebGoat/CrossSiteScripting/stored"
    assert stored in state.endpoints
    assert state.endpoints[stored]["method"] == "POST"
    stored_names = {p["name"] for p in state.endpoints[stored]["params"]}
    assert "comment" in stored_names
