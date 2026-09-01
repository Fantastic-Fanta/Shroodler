from __future__ import annotations

from shroodler.crawler import crawl_url


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
