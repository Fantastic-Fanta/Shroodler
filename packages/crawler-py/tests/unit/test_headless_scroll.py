from __future__ import annotations

from shroodler.crawler import crawl_url


def test_headless_infinite_scroll_terminates(fx):
    fx.html(
        "/",
        """
        <div id="list"><a href="/page/1">1</a></div>
        <script>
          let n = 1;
          const id = setInterval(() => {
            n += 1;
            const a = document.createElement('a');
            a.href = '/page/' + n;
            a.textContent = String(n);
            document.getElementById('list').appendChild(a);
            if (n > 50) clearInterval(id);
          }, 10);
        </script>
        """,
    )
    fx.prefix(
        "/page/",
        lambda req: (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            b"<html>ok</html>",
        ),
    )
    result = crawl_url(fx.origin + "/", mode="headless", depth=2, max_pages=20)
    assert len(result.pages) <= 20
